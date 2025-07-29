#!/bin/bash
set -e

PROG_NAME="tls_rate_limiter"
IFACE=""
SHOW_LOGS=false

# Parse command-line arguments
for arg in "$@"; do
    case $arg in
        --logs)
        SHOW_LOGS=true
        shift # Remove --logs from processing
        ;;
        *)
        # Assume any other argument is the interface
        IFACE="$arg"
        ;;
    esac
done

# Check if an interface was provided
if [ -z "$IFACE" ]; then
    echo "Usage: $0 <interface> [--logs]"
    echo "e.g., $0 eth0"
    echo "e.g., $0 eth0 --logs"
    exit 1
fi

# Unload any existing XDP program from the interface.
# We add '|| true' to prevent the script from exiting if no program was loaded.
echo "Attempting to unload existing XDP program from $IFACE (if any)..."
sudo ip link set dev $IFACE xdp off || true

# Compile the XDP program
make clean
if [ "$SHOW_LOGS" = true ]; then
    make DEBUG_LOG=1
else
    make
fi

echo "Loading XDP program onto interface $IFACE..."

# Load the XDP program. `xdp generic` is used for broad compatibility.
# If your driver supports it, you can use `xdpdrv` for native mode.
sudo ip link set dev $IFACE xdp obj ${PROG_NAME}.o sec xdp

echo "✅ XDP program loaded successfully on interface '$IFACE'."

if [ "$SHOW_LOGS" = true ]; then
    echo "   Displaying logs. Press Ctrl+C to stop."
    sudo cat /sys/kernel/debug/tracing/trace_pipe
else
    echo "   To view logs, run the script with the --logs flag or use the command:"
    echo "   sudo cat /sys/kernel/debug/tracing/trace_pipe"
fi
