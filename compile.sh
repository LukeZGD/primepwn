#!/bin/bash

if test -z "$PREFIX"; then
    PREFIX="/usr/local"
else
    echo "NOTE: Using externally defined PREFIX. If that's not what you want, run: unset PREFIX"
fi
echo "PREFIX: $PREFIX"

set -e

libplist_ver=2.0.4
limd_glue_ver=1.0.0
libirecovery_ver=1.0.5

limd() {
    local file="$1"

    for lib in \
        "libplist-$libplist_ver.dylib" \
        "libimobiledevice-glue-$limd_glue_ver.dylib" \
        "libirecovery-$libirecovery_ver.dylib"
    do
        install_name_tool -change \
            "$PREFIX/lib/$lib" \
            "@executable_path/lib/$lib" \
            "$file"
    done
}

fix_dylib() {
    local file="$1"
    shift

    install_name_tool -id "@loader_path/$(basename "$file")" "$file"

    for lib in "$@"; do
        install_name_tool -change \
            "$PREFIX/lib/$lib" \
            "@loader_path/$lib" \
            "$file"
    done
}

if [[ $(uname) == "Darwin" ]]; then
    platform="macos"
    echo "* Platform: macOS"
    echo "This assumes you have already run limd-build-macos script."
    export MACOSX_DEPLOYMENT_TARGET=10.11

    mkdir -p output/lib
    gcc primepwn.c -o output/primepwn -lirecovery-1.0 -arch x86_64 -arch arm64

    limd "output/primepwn"

    cp $PREFIX/lib/libplist-$libplist_ver.dylib \
       $PREFIX/lib/libimobiledevice-glue-$limd_glue_ver.dylib \
       $PREFIX/lib/libirecovery-$libirecovery_ver.dylib \
       output/lib/

    pushd output/lib

    fix_dylib \
        "libplist-$libplist_ver.dylib"

    fix_dylib \
        "libimobiledevice-glue-$limd_glue_ver.dylib" \
        "libplist-$libplist_ver.dylib"

    fix_dylib \
        "libirecovery-$libirecovery_ver.dylib" \
        "libimobiledevice-glue-$limd_glue_ver.dylib" \
        "libplist-$libplist_ver.dylib"

    popd

elif [[ $OSTYPE == "linux"* ]]; then
    platform="linux"
    echo "* Platform: Linux"
    if [[ ! -f "/etc/lsb-release" && ! -f "/etc/debian_version" ]]; then
        echo "[Error] Ubuntu/Debian only"
        exit 1
    fi

    rm -rf tmp
    mkdir bin tmp 2>/dev/null
    cd tmp

    export PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig
    export JNUM="-j$(nproc)"
    export DIR=$(pwd)
    export FR_BASE="$DIR"
    export CC_ARGS="CC=/usr/bin/gcc CXX=/usr/bin/g++ LD=/usr/bin/ld RANLIB=/usr/bin/ranlib AR=/usr/bin/ar"
    export ALT_CC_ARGS="CC=/usr/bin/gcc CXX=/usr/bin/g++ LD=/usr/bin/ld RANLIB=/usr/bin/ranlib AR=/usr/bin/ar"
    export CONF_ARGS="--disable-dependency-tracking --disable-silent-rules --prefix=$PREFIX --disable-shared --enable-debug --without-cython"
    export ALT_CONF_ARGS="--disable-dependency-tracking --disable-silent-rules --prefix=$PREFIX"
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
    git clone https://github.com/libimobiledevice/libplist
    git clone https://github.com/libimobiledevice/libimobiledevice-glue
    git clone https://github.com/synackuk/libirecovery

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
    cp $PREFIX/bin/irecovery primepwn
fi

echo "Done!"
