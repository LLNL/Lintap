#!/bin/bash
# Convenience script to run the unified tracer with common options

set -e

# Check for root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Build if needed
if [ ! -d "bin" ]; then
    echo "Building project..."
    dotnet build
fi

# Run the tracer
echo "Starting eBPF Unified System Tracer..."
dotnet run --no-build "$@"
