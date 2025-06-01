#!/bin/bash
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig
export JNUM="-j$(nproc)"

rm -rf tmp
mkdir bin tmp 2>/dev/null
cd tmp

set -e

if [[ $OSTYPE == "linux"* ]]; then
    platform="linux"
    echo "* Platform: Linux"
    if [[ ! -f "/etc/lsb-release" && ! -f "/etc/debian_version" ]]; then
        echo "[Error] Ubuntu/Debian only"
        exit 1
    fi

    export DIR=$(pwd)
    export FR_BASE="$DIR"
    export CC_ARGS="CC=/usr/bin/gcc CXX=/usr/bin/g++ LD=/usr/bin/ld RANLIB=/usr/bin/ranlib AR=/usr/bin/ar"
    export ALT_CC_ARGS="CC=/usr/bin/gcc CXX=/usr/bin/g++ LD=/usr/bin/ld RANLIB=/usr/bin/ranlib AR=/usr/bin/ar"
    export CONF_ARGS="--disable-dependency-tracking --disable-silent-rules --prefix=/usr/local --disable-shared --enable-debug --without-cython"
    export ALT_CONF_ARGS="--disable-dependency-tracking --disable-silent-rules --prefix=/usr/local"
    if [[ $(uname -m) == "a"* && $(getconf LONG_BIT) == 64 ]]; then
        export LD_ARGS="-Wl,--allow-multiple-definition -L/usr/lib/aarch64-linux-gnu -lzstd -llzma -lbz2"
    elif [[ $(uname -m) == "a"* ]]; then
        export LD_ARGS="-Wl,--allow-multiple-definition -L/usr/lib/arm-linux-gnueabihf -lzstd -llzma -lbz2"
    else
        export LD_ARGS="-Wl,--allow-multiple-definition -L/usr/lib/x86_64-linux-gnu -lzstd -llzma -lbz2"
    fi

    echo "If prompted, enter your password"
    sudo echo -n ""
    echo "Downloading apt deps"
    sudo apt update
    sudo apt install -y curl build-essential checkinstall git autoconf automake libtool-bin pkg-config cmake libusb-1.0-0-dev libusb-dev libpng-dev libreadline-dev libzstd-dev python3-dev autopoint
    echo "Done"

    echo "Cloning git repos and other deps"
    git clone https://github.com/LukeeGD/libplist
    git clone https://github.com/LukeeGD/libimobiledevice-glue
    git clone https://github.com/LukeeGD/libirecovery

    echo "Building libplist..."
    cd $FR_BASE
    cd libplist
    ./autogen.sh $CONF_ARGS $CC_ARGS
    make $JNUM
    sudo make $JNUM install

    echo "Building libimobiledevice-glue..."
    cd $FR_BASE
    cd libimobiledevice-glue
    ./autogen.sh $CONF_ARGS $CC_ARGS
    make $JNUM
    sudo make $JNUM install

    echo "Building libirecovery..."
    cd $FR_BASE
    cd libirecovery
    cp ../../*.h include/
    cp ../../primepwn.c tools/irecovery.c
    ./autogen.sh $CONF_ARGS $CC_ARGS
    make $JNUM
    sudo make $JNUM install

    cd $FR_BASE
    cd ..
    cp /usr/local/bin/irecovery primepwn
fi

echo "Done!"
