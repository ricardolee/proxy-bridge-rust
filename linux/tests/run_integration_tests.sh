#!/usr/bin/env bash
set -euo pipefail

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (or via sudo) to modify network namespaces and nftables rules."
    exit 1
fi

NS_NAME="pb_test_ns"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LINUX_DIR="${WORKSPACE_DIR}/linux"
BIN_PATH="${LINUX_DIR}/target/debug/proxy-bridge"

echo "=== ProxyBridge Sandboxed Integration Tests ==="
echo "Workspace: ${WORKSPACE_DIR}"
echo "Binary: ${BIN_PATH}"

# Build the proxy-bridge binary (output to linux/target/)
if [ -n "${SUDO_USER:-}" ]; then
    echo "Building proxy-bridge as user ${SUDO_USER}..."
    sudo -u "$SUDO_USER" env PATH="$PATH" HOME="/home/${SUDO_USER}" cargo build --manifest-path "${WORKSPACE_DIR}/Cargo.toml" -p proxy-bridge-linux --target-dir "${LINUX_DIR}/target"
else
    echo "Building proxy-bridge..."
    cargo build --manifest-path "${WORKSPACE_DIR}/Cargo.toml" -p proxy-bridge-linux --target-dir "${LINUX_DIR}/target"
fi

# Cleanup function to run on exit
cleanup() {
    echo "=== Cleaning Up Sandbox ==="
    # Kill background jobs by PGID or specific PIDs if set
    if [ -f "${SCRIPT_DIR}/mock.pid" ]; then
        MOCK_PID=$(cat "${SCRIPT_DIR}/mock.pid")
        echo "Stopping mock servers (PID: ${MOCK_PID})..."
        kill -9 "$MOCK_PID" 2>/dev/null || true
        rm -f "${SCRIPT_DIR}/mock.pid"
    fi
    if [ -f "${SCRIPT_DIR}/pb.pid" ]; then
        PB_PID=$(cat "${SCRIPT_DIR}/pb.pid")
        echo "Stopping ProxyBridge (PID: ${PB_PID})..."
        kill -2 "$PB_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$PB_PID" 2>/dev/null || true
        rm -f "${SCRIPT_DIR}/pb.pid"
    fi

    # Delete network namespace
    if ip netns list | grep -q "$NS_NAME"; then
        echo "Deleting network namespace ${NS_NAME}..."
        ip netns del "$NS_NAME"
    fi
    echo "Cleanup complete."
}
trap cleanup EXIT

# 1. Create isolated network namespace with dummy interface
echo "Creating isolated network namespace ${NS_NAME}..."
ip netns add "$NS_NAME"
ip netns exec "$NS_NAME" ip link set lo up

# Add a dummy interface with non-loopback IPs.
# ProxyBridge correctly skips proxying loopback (127.x.x.x) traffic,
# so we need real-looking IPs for the test to exercise the proxy path.
ip netns exec "$NS_NAME" ip link add dummy0 type dummy
ip netns exec "$NS_NAME" ip addr add 10.99.0.1/24 dev dummy0
ip netns exec "$NS_NAME" ip addr add 10.99.0.2/24 dev dummy0
ip netns exec "$NS_NAME" ip link set dummy0 up

# 2. Start mock servers in namespace
echo "Starting mock SOCKS5 and target HTTP servers inside the namespace..."
ip netns exec "$NS_NAME" python3 "${SCRIPT_DIR}/mock_servers.py" > "${SCRIPT_DIR}/mock.log" 2>&1 &
echo $! > "${SCRIPT_DIR}/mock.pid"

# Give mock servers a moment to spin up
sleep 1.5

# Verify mock servers are up
if ! ip netns exec "$NS_NAME" ss -ltn | grep -q '10.99.0.1:1080'; then
    echo "Error: Mock SOCKS5 server failed to start. Logs:"
    cat "${SCRIPT_DIR}/mock.log"
    exit 1
fi
if ! ip netns exec "$NS_NAME" ss -ltn | grep -q '10.99.0.2:80'; then
    echo "Error: Mock target HTTP server failed to start. Logs:"
    cat "${SCRIPT_DIR}/mock.log"
    exit 1
fi
echo "Mock servers are up and listening inside the namespace."

# 3. Test Direct Bypass before ProxyBridge is started
echo "Testing Direct Bypass (without ProxyBridge running)..."
DIRECT_RESP=$(ip netns exec "$NS_NAME" curl -s --connect-timeout 2 http://10.99.0.2:80/)
if [ "${DIRECT_RESP}" != "Hello, Target" ]; then
    echo "Error: Direct bypass failed. Expected 'Hello, Target', got '${DIRECT_RESP}'"
    exit 1
fi
echo "Direct bypass test passed."

# 4. Start ProxyBridge with TCP rule for curl
echo "Starting ProxyBridge inside the namespace with rule 'curl:*:*:both:proxy'..."
ip netns exec "$NS_NAME" "$BIN_PATH" --proxy socks5://10.99.0.1:1080 --rule "curl:*:*:both:proxy" --verbose 2 > "${SCRIPT_DIR}/pb.log" 2>&1 &
echo $! > "${SCRIPT_DIR}/pb.pid"

# Give ProxyBridge a moment to hook into NFQUEUE and set rules
sleep 2.5

echo "=== Installed nftables Ruleset ==="
ip netns exec "$NS_NAME" nft list ruleset || true
echo "=================================="

# 5. Execute Scenario A: Matched Proxying via curl
echo "Scenario A: Executing curl (should be proxied)..."
PROXY_RESP=$(ip netns exec "$NS_NAME" curl -s --connect-timeout 5 http://10.99.0.2:80/)
if [ "${PROXY_RESP}" != "Hello, Target" ]; then
    echo "Error: Proxied request failed. Expected 'Hello, Target', got '${PROXY_RESP}'"
    echo "=== ProxyBridge Logs ==="
    cat "${SCRIPT_DIR}/pb.log"
    echo "=== Mock Proxy Logs ==="
    cat "${SCRIPT_DIR}/mock.log"
    exit 1
fi

# Verify the mock proxy actually saw the request
if ! grep -q "SOCKS5: proxying request to 10.99.0.2:80" "${SCRIPT_DIR}/mock.log"; then
    echo "Error: SOCKS5 proxy logs do not show the request was intercepted!"
    echo "=== Mock Proxy Logs ==="
    cat "${SCRIPT_DIR}/mock.log"
    exit 1
fi
echo "[SUCCESS] Scenario A Passed: curl traffic was successfully intercepted and proxied!"

# 6. Execute Scenario B: Direct bypass when using different binary (wget)
echo "Scenario B: Executing wget (should NOT be proxied)..."
# Clear mock proxy log so we can verify no new proxy requests occur
truncate -s 0 "${SCRIPT_DIR}/mock.log"

WGET_RESP=$(ip netns exec "$NS_NAME" wget -qO- --timeout=2 http://10.99.0.2:80/)
if [ "${WGET_RESP}" != "Hello, Target" ]; then
    echo "Error: Direct bypass via wget failed. Expected 'Hello, Target', got '${WGET_RESP}'"
    exit 1
fi

if grep -q "SOCKS5: proxying request" "${SCRIPT_DIR}/mock.log"; then
    echo "Error: SOCKS5 proxy saw the wget request, but it should have been direct!"
    exit 1
fi
echo "[SUCCESS] Scenario B Passed: wget traffic bypassed the proxy."

# 7. Execute Scenario C: Blocking traffic
echo "Scenario C: Testing Blocking Rule..."
# Stop old ProxyBridge
PB_PID=$(cat "${SCRIPT_DIR}/pb.pid")
kill -2 "$PB_PID" || true
sleep 1
rm -f "${SCRIPT_DIR}/pb.pid"

# Restart with block rule for curl
echo "Restarting ProxyBridge with 'curl:*:*:both:block' rule..."
ip netns exec "$NS_NAME" "$BIN_PATH" --proxy socks5://10.99.0.1:1080 --rule "curl:*:*:both:block" --verbose 2 > "${SCRIPT_DIR}/pb.log" 2>&1 &
echo $! > "${SCRIPT_DIR}/pb.pid"
sleep 2.5

echo "Executing curl (should be blocked)..."
if ip netns exec "$NS_NAME" curl -s --connect-timeout 2 http://10.99.0.2:80/ >/dev/null 2>&1; then
    echo "Error: curl request succeeded but it should have been blocked!"
    exit 1
else
    echo "[SUCCESS] Scenario C Passed: curl traffic was successfully blocked."
fi

echo ""
echo "=================================================="
echo "🎉 🎉 🎉 All Integration Tests Passed Successfully! 🎉 🎉 🎉"
echo "=================================================="
