#!/bin/bash

# Get additional build flags from command line arguments
BUILD_FLAGS="$@"

# List of devices to build
DEVICES=("x1s" "y2s" "z3s" "c1s" "c2s" "r8s")

rm -rf build/out/all/

for device in "${DEVICES[@]}"; do
    echo "Building for device: $device"
    ./build.sh -m "$device" -k y 
    
    # Check if build was successful
    if [ $? -ne 0 ]; then
        echo "Error: Build failed for $device"
        exit 1
    fi
done

echo "All builds completed successfully"
echo "Creating symlinks..."
mkdir -p build/out/all/zip && \
find build/out -iname "*zip" -type f -exec ln -sf $(realpath --relative-to=build/out/all/zip {}) build/out/all/zip/ \;

echo "Symlinks created in build/out/all/zip/"