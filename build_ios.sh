#!/bin/sh
set -e
PROJECT_DIR=${PWD}
echo "project directory is:" ${PROJECT_DIR}

echo "init git sub modules."
git submodule init
git submodule update

echo "compiling boring ssl"
BORINGSSL_DIR=${PROJECT_DIR}/boringssl
echo "boringssl directory is:" ${BORINGSSL_DIR}

echo "compiling boring ssl arch: i386"
cd ${BORINGSSL_DIR}
rm -rf build_i386
mkdir build_i386
cd build_i386
cmake -S .. -DCMAKE_OSX_SYSROOT=iphonesimulator -DCMAKE_OSX_ARCHITECTURES=i386 -DCMAKE_BUILD_TYPE=Release
make -j8

echo "compiling boring ssl arch: x86_64"
cd ${BORINGSSL_DIR}
rm -rf build_x86_64
mkdir build_x86_64 && cd build_x86_64
cmake -S .. -DCMAKE_OSX_SYSROOT=iphonesimulator -DCMAKE_OSX_ARCHITECTURES=x86_64 -DCMAKE_BUILD_TYPE=Release
make -j8

echo "compiling boring ssl arch: arm64"
cd ${BORINGSSL_DIR}
rm -rf build_arm64
mkdir build_arm64 && cd build_arm64
cmake -S .. -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_BUILD_TYPE=Release
make -j8

echo "compiling boring ssl arch: armv7"
cd ${BORINGSSL_DIR}
rm -rf build_armv7
mkdir build_armv7 && cd build_armv7
cmake -S .. -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_OSX_ARCHITECTURES=armv7 -DCMAKE_BUILD_TYPE=Release
make -j8

echo "merging libssl arch"
cd ${BORINGSSL_DIR}
 lipo -create -o libssl.a ${BORINGSSL_DIR}/build_arm64/ssl/libssl.a  ${BORINGSSL_DIR}/build_armv7/ssl/libssl.a  ${BORINGSSL_DIR}/build_i386/ssl/libssl.a  ${BORINGSSL_DIR}/build_x86_64/ssl/libssl.a
 
echo "merging libcrypto arch"
lipo -create -o libcrypto.a ${BORINGSSL_DIR}/build_arm64/crypto/libcrypto.a  ${BORINGSSL_DIR}/build_armv7/crypto/libcrypto.a  ${BORINGSSL_DIR}/build_i386/crypto/libcrypto.a  ${BORINGSSL_DIR}/build_x86_64/crypto/libcrypto.a

rm -rf ${BORINGSSL_DIR}/build_arm64 ${BORINGSSL_DIR}/build_armv7  ${BORINGSSL_DIR}/build_i386 ${BORINGSSL_DIR}/build_x86_64
echo "compiling boring ssl finished"


echo "compiling libevent"
echo "compiling libevent arch: i386"
LIBEVENT_DIR=${PROJECT_DIR}/libevent
echo "libevent directory is:" ${LIBEVENT_DIR}

echo "compiling libevent arch: i386"
cd ${LIBEVENT_DIR}
rm -rf build_i386
mkdir build_i386 && cd build_i386
cmake -S .. -DCMAKE_OSX_ARCHITECTURES=i386 -DCMAKE_OSX_SYSROOT=iphonesimulator -DCMAKE_BUILD_TYPE=Release -DEVENT__DISABLE_OPENSSL=ON
make

echo "compiling libevent arch: x86_64"
cd ${LIBEVENT_DIR}
rm -rf build_x86_64
mkdir build_x86_64 && cd build_x86_64
cmake -S .. -DCMAKE_OSX_ARCHITECTURES=x86_64 -DCMAKE_OSX_SYSROOT=iphonesimulator -DCMAKE_BUILD_TYPE=Release -DEVENT__DISABLE_OPENSSL=ON
make

echo "compiling libevent arch: arm64"
cd ${LIBEVENT_DIR}
rm -rf build_arm64
mkdir build_arm64 && cd build_arm64
cmake -S .. -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_BUILD_TYPE=Release -DEVENT__DISABLE_OPENSSL=ON
make

echo "compiling libevent arch: armv7"
cd ${LIBEVENT_DIR}
rm -rf build_armv7
mkdir build_armv7 && cd build_armv7
cmake -S .. -DCMAKE_OSX_ARCHITECTURES=armv7 -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_BUILD_TYPE=Release -DEVENT__DISABLE_OPENSSL=ON
make

echo "merging libevent lib arch"
cd ${LIBEVENT_DIR}
lipo -create -o libevent.a build_i386/lib/libevent.a build_x86_64/lib/libevent.a build_arm64/lib/libevent.a build_armv7/lib/libevent.a
rm -rf build_i386 build_x86_64 build_arm64 build_armv7
echo "compiling libevent finished"

echo "compiling lsquic"
echo "compiling lsquic arch: i386"
cd ${PROJECT_DIR}
rm -rf build_i386
mkdir build_i386 && cd build_i386
cmake -S .. -DBORINGSSL_INCLUDE=${BORINGSSL_DIR}/include -DBORINGSSL_LIB_crypto=${BORINGSSL_DIR}/libcrypto.a -DBORINGSSL_LIB_ssl=${BORINGSSL_DIR}/libssl.a -DCMAKE_OSX_ARCHITECTURES=i386 -DCMAKE_OSX_SYSROOT=iphonesimulator  -DCMAKE_BUILD_TYPE=Release
make lsquic

echo "compiling lsquic arch: x86_64"
cd ${PROJECT_DIR}
rm -rf build_x86_64
mkdir build_x86_64 && cd build_x86_64
cmake -S .. -DBORINGSSL_INCLUDE=${BORINGSSL_DIR}/include -DBORINGSSL_LIB_crypto=${BORINGSSL_DIR}/libcrypto.a -DBORINGSSL_LIB_ssl=${BORINGSSL_DIR}/libssl.a -DCMAKE_OSX_ARCHITECTURES=x86_64 -DCMAKE_OSX_SYSROOT=iphonesimulator  -DCMAKE_BUILD_TYPE=Release
make lsquic

echo "compiling lsquic arch: arm64"
cd ${PROJECT_DIR}
rm -rf build_arm64
mkdir build_arm64 && cd build_arm64
cmake -S .. -DBORINGSSL_INCLUDE=${BORINGSSL_DIR}/include -DBORINGSSL_LIB_crypto=${BORINGSSL_DIR}/libcrypto.a -DBORINGSSL_LIB_ssl=${BORINGSSL_DIR}/libssl.a -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_BUILD_TYPE=Release
make lsquic

echo "compiling lsquic arch: armv7"
cd ${PROJECT_DIR}
rm -rf build_armv7
mkdir build_armv7 && cd build_armv7
cmake -S .. -DBORINGSSL_INCLUDE=${BORINGSSL_DIR}/include -DBORINGSSL_LIB_crypto=${BORINGSSL_DIR}/libcrypto.a -DBORINGSSL_LIB_ssl=${BORINGSSL_DIR}/libssl.a -DCMAKE_OSX_ARCHITECTURES=armv7 -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_BUILD_TYPE=Release
make lsquic

echo "merging lsquic lib arch"
cd ${PROJECT_DIR}
lipo -create -o liblsquic.a ${PROJECT_DIR}/build_i386/src/liblsquic/liblsquic.a ${PROJECT_DIR}/build_x86_64/src/liblsquic/liblsquic.a  ${PROJECT_DIR}/build_arm64/src/liblsquic/liblsquic.a ${PROJECT_DIR}/build_armv7/src/liblsquic/liblsquic.a
rm -rf ${PROJECT_DIR}/build_i386 ${PROJECT_DIR}/build_x86_64 ${PROJECT_DIR}/build_arm64 ${PROJECT_DIR}/build_armv7
echo "compiling lsquic finished"

cp -R ${BORINGSSL_DIR}/libssl.a libssl.a
cp -R ${BORINGSSL_DIR}/libcrypto.a libcrypto.a
cp -R ${LIBEVENT_DIR}/libevent.a libevent.a
echo "done"
