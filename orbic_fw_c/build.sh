#!/bin/bash
set -e

# --- 1. Detect Cross-Compiler ---
# First check for local toolchain with kernel 3.2 headers (kernel 3.x compatible)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_GCC="$SCRIPT_DIR/../gcc_mac/bin/arm-cortex_a8-linux-gnueabi-gcc"

CC=""
if [ -f "$LOCAL_GCC" ]; then
    CC="$LOCAL_GCC"
    # Add toolchain bin to PATH so GCC can find cc1 in libexec
    export PATH="$SCRIPT_DIR/../gcc_mac/bin:$PATH"
    echo "Found local kernel 3.2 toolchain: $CC"
else
    # Fallback to system PATH - try armv7 first (glibc 2.17), then others
    for candidate in "armv7-unknown-linux-gnueabihf-gcc" "arm-none-linux-gnueabihf-gcc" "arm-unknown-linux-gnueabihf-gcc"; do
        if command -v "$candidate" &> /dev/null; then
            CC="$candidate"
            echo "Found cross-compiler: $CC"
            break
        fi
    done
fi

if [ -z "$CC" ]; then
    echo "ERROR: Cross-compiler not found!"
    echo "Download GCC 8.3.0 for macOS from:"
    echo "  https://github.com/thinkski/osx-arm-linux-toolchains/releases"
    echo "Extract to: gcc_mac/arm-unknown-linux-gnueabihf/"
    exit 1
fi


# --- 2. Build BearSSL for macOS (separate from Windows library) ---
BEARSSL_DIR="bearssl_mac"
BEARSSL_LIB="$BEARSSL_DIR/libbearssl.a"

if [ ! -f "$BEARSSL_LIB" ]; then
    echo "Building BearSSL for macOS cross-compile..."
    
    mkdir -p "$BEARSSL_DIR"
    cd "$BEARSSL_DIR"
    
    # Download if not present
    if [ ! -d "bearssl-0.6" ]; then
        if [ ! -f "bearssl-0.6.tar.gz" ]; then
            echo "Downloading BearSSL 0.6..."
            curl -O https://bearssl.org/bearssl-0.6.tar.gz
        fi
        echo "Extracting BearSSL..."
        tar -xzf bearssl-0.6.tar.gz
    fi

    # Build with BR_USE_URANDOM to avoid getentropy (not in old glibc)
    echo "Compiling BearSSL..."
    cd bearssl-0.6
    make lib CC="$CC" LD="$CC" AR="${CC%-gcc}-ar" CFLAGS="-W -Wall -Os -DBR_USE_URANDOM"
    
    # Copy library up
    cp build/libbearssl.a ../
    cd ../..
    echo "BearSSL built: $BEARSSL_LIB"
else
    echo "Found $BEARSSL_LIB, skipping build."
fi

# --- 3. Build Firmware ---
echo "Building orbic_app..."
$CC main.c gps.c wifi.c wigle.c clients.c nettools.c -o orbic_app -I. -L"$BEARSSL_DIR" -lbearssl -static

if [ $? -eq 0 ]; then
    echo "Build Successful: orbic_app"
    ls -lh orbic_app
    file orbic_app
else
    echo "Build Failed: orbic_app"
    exit 1
fi

# --- 4. Build Boot Helper ---
if [ -f "dagshell_boot.c" ]; then
    echo "Building dagshell_boot..."
    $CC dagshell_boot.c -o dagshell_boot -static
    if [ $? -eq 0 ]; then
        echo "Build Successful: dagshell_boot"
        ls -lh dagshell_boot
    else
        echo "Build Failed: dagshell_boot"
    fi
fi

echo "All tasks complete."
