#!/bin/bash
set -e

# The network interface to detach from
IFACE=$1

# Check if an interface was provided
if [ -z "$IFACE" ]; then
    echo "Usage: $0 <interface>"
    echo "e.g., $0 eth0"
    exit 1
fi

echo "Unloading XDP program from interface $IFACE..."

# Detach the XDP program by setting the mode to 'off'
sudo ip link set dev $IFACE xdp off

# Clean up the compiled object file
make clean

echo "✅ XDP program unloaded successfully from '$IFACE'."
