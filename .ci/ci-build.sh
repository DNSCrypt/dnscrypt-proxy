#! /bin/sh

PACKAGE_VERSION="$1"

cd dnscrypt-proxy || exit 1

go clean
env GOOS=windows GOARCH=386 go build -mod vendor -ldflags="-s -w"
mkdir win32
ln dnscrypt-proxy.exe win32/
cp ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt win32/
for i in win32/LICENSE win32/*.toml win32/*.txt; do ex -bsc '%!awk "{sub(/$/,\"\r\")}1"' -cx "$i"; done
ln ../windows/* win32/
zip -9 -r dnscrypt-proxy-win32-${PACKAGE_VERSION:-dev}.zip win32

go clean
env GOOS=windows GOARCH=amd64 go build -mod vendor -ldflags="-s -w"
mkdir win64
ln dnscrypt-proxy.exe win64/
cp ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt win64/
for i in win64/LICENSE win64/*.toml win64/*.txt; do ex -bsc '%!awk "{sub(/$/,\"\r\")}1"' -cx "$i"; done
ln ../windows/* win64/
zip -9 -r dnscrypt-proxy-win64-${PACKAGE_VERSION:-dev}.zip win64

go clean
env GO386=387 GOOS=openbsd GOARCH=386 go build -mod vendor -ldflags="-s -w"
mkdir openbsd-i386
ln dnscrypt-proxy openbsd-i386/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt openbsd-i386/
tar czpvf dnscrypt-proxy-openbsd_i386-${PACKAGE_VERSION:-dev}.tar.gz openbsd-i386

go clean
env GOOS=openbsd GOARCH=amd64 go build -mod vendor -ldflags="-s -w"
mkdir openbsd-amd64
ln dnscrypt-proxy openbsd-amd64/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt openbsd-amd64/
tar czpvf dnscrypt-proxy-openbsd_amd64-${PACKAGE_VERSION:-dev}.tar.gz openbsd-amd64

go clean
env GOOS=freebsd GOARCH=386 go build -mod vendor -ldflags="-s -w"
mkdir freebsd-i386
ln dnscrypt-proxy freebsd-i386/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt freebsd-i386/
tar czpvf dnscrypt-proxy-freebsd_i386-${PACKAGE_VERSION:-dev}.tar.gz freebsd-i386

go clean
env GOOS=freebsd GOARCH=amd64 go build -mod vendor -ldflags="-s -w"
mkdir freebsd-amd64
ln dnscrypt-proxy freebsd-amd64/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt freebsd-amd64/
tar czpvf dnscrypt-proxy-freebsd_amd64-${PACKAGE_VERSION:-dev}.tar.gz freebsd-amd64

go clean
env GOOS=freebsd GOARCH=arm GOARM=5 go build -mod vendor -ldflags="-s -w"
mkdir freebsd-arm
ln dnscrypt-proxy freebsd-arm/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt freebsd-arm/
tar czpvf dnscrypt-proxy-freebsd_arm-${PACKAGE_VERSION:-dev}.tar.gz freebsd-arm

go clean
env GOOS=dragonfly GOARCH=amd64 go build -mod vendor -ldflags="-s -w"
mkdir dragonflybsd-amd64
ln dnscrypt-proxy dragonflybsd-amd64/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt dragonflybsd-amd64/
tar czpvf dnscrypt-proxy-dragonflybsd_amd64-${PACKAGE_VERSION:-dev}.tar.gz dragonflybsd-amd64

go clean
env GOOS=netbsd GOARCH=386 go build -mod vendor -ldflags="-s -w"
mkdir netbsd-i386
ln dnscrypt-proxy netbsd-i386/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt netbsd-i386/
tar czpvf dnscrypt-proxy-netbsd_i386-${PACKAGE_VERSION:-dev}.tar.gz netbsd-i386

go clean
env GOOS=netbsd GOARCH=amd64 go build -mod vendor -ldflags="-s -w"
mkdir netbsd-amd64
ln dnscrypt-proxy netbsd-amd64/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt netbsd-amd64/
tar czpvf dnscrypt-proxy-netbsd_amd64-${PACKAGE_VERSION:-dev}.tar.gz netbsd-amd64

go clean
env GOOS=solaris GOARCH=amd64 go build -mod vendor -ldflags="-s -w"
mkdir solaris-amd64
ln dnscrypt-proxy solaris-amd64/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt solaris-amd64/
tar czpvf dnscrypt-proxy-solaris_amd64-${PACKAGE_VERSION:-dev}.tar.gz solaris-amd64

go clean
env CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -mod vendor -ldflags="-s -w"
mkdir linux-i386
ln dnscrypt-proxy linux-i386/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt linux-i386/
tar czpvf dnscrypt-proxy-linux_i386-${PACKAGE_VERSION:-dev}.tar.gz linux-i386

go clean
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod vendor -ldflags="-s -w"
mkdir linux-x86_64
ln dnscrypt-proxy linux-x86_64/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt linux-x86_64/
tar czpvf dnscrypt-proxy-linux_x86_64-${PACKAGE_VERSION:-dev}.tar.gz linux-x86_64

go clean
env CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 go build -mod vendor -ldflags="-s -w"
mkdir linux-arm
ln dnscrypt-proxy linux-arm/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt linux-arm/
tar czpvf dnscrypt-proxy-linux_arm-${PACKAGE_VERSION:-dev}.tar.gz linux-arm

go clean
env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -mod vendor -ldflags="-s -w"
mkdir linux-arm64
ln dnscrypt-proxy linux-arm64/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt linux-arm64/
tar czpvf dnscrypt-proxy-linux_arm64-${PACKAGE_VERSION:-dev}.tar.gz linux-arm64

go clean
env CGO_ENABLED=0 GOOS=linux GOARCH=mips GOMIPS=softfloat go build -mod vendor -ldflags="-s -w"
mkdir linux-mips
ln dnscrypt-proxy linux-mips/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt linux-mips/
tar czpvf dnscrypt-proxy-linux_mips-${PACKAGE_VERSION:-dev}.tar.gz linux-mips

go clean
env CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -mod vendor -ldflags="-s -w"
mkdir linux-mipsle
ln dnscrypt-proxy linux-mipsle/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt linux-mipsle/
tar czpvf dnscrypt-proxy-linux_mipsle-${PACKAGE_VERSION:-dev}.tar.gz linux-mipsle

go clean
env CGO_ENABLED=0 GOOS=linux GOARCH=mips64 GOMIPS64=softfloat go build -mod vendor -ldflags="-s -w"
mkdir linux-mips64
ln dnscrypt-proxy linux-mips64/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt linux-mips64/
tar czpvf dnscrypt-proxy-linux_mips64-${PACKAGE_VERSION:-dev}.tar.gz linux-mips64

go clean
env CGO_ENABLED=0 GOOS=linux GOARCH=mips64le GOMIPS64=softfloat go build -mod vendor -ldflags="-s -w"
mkdir linux-mips64le
ln dnscrypt-proxy linux-mips64le/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt linux-mips64le/
tar czpvf dnscrypt-proxy-linux_mips64le-${PACKAGE_VERSION:-dev}.tar.gz linux-mips64le

go clean
env CGO_ENABLED=0 GOOS=linux GOARCH=riscv64 go build -mod vendor -ldflags="-s -w"
mkdir linux-riscv64
ln dnscrypt-proxy linux-riscv64/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt linux-riscv64/
tar czpvf dnscrypt-proxy-linux_riscv64-${PACKAGE_VERSION:-dev}.tar.gz linux-riscv64

go clean
env GOOS=darwin GOARCH=amd64 go build -mod vendor -ldflags="-s -w"
mkdir macos-x86_64
ln dnscrypt-proxy macos-x86_64/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt macos-x86_64/
tar czpvf dnscrypt-proxy-macos_x86_64-${PACKAGE_VERSION:-dev}.tar.gz macos-x86_64

go clean
env GOOS=darwin GOARCH=arm64 go build -mod vendor -ldflags="-s -w"
mkdir macos-arm64
ln dnscrypt-proxy macos-arm64/
ln ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt macos-arm64/
tar czpvf dnscrypt-proxy-macos_arm64-${PACKAGE_VERSION:-dev}.tar.gz macos-arm64

# Android

NDK_VER=r20
curl -LOs https://dl.google.com/android/repository/android-ndk-${NDK_VER}-linux-x86_64.zip
unzip -q android-ndk-${NDK_VER}-linux-x86_64.zip -d ${HOME}
rm android-ndk-${NDK_VER}-linux-x86_64.zip
NDK_TOOLS=${HOME}/android-ndk-${NDK_VER}
export PATH=${PATH}:${NDK_TOOLS}/toolchains/llvm/prebuilt/linux-x86_64/bin

go clean
env CC=armv7a-linux-androideabi19-clang CXX=armv7a-linux-androideabi19-clang++ CGO_ENABLED=1 GOOS=android GOARCH=arm GOARM=7 go build -mod vendor -ldflags="-s -w"
mkdir android-arm
ln dnscrypt-proxy android-arm/
cp ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt android-arm/
zip -9 -r dnscrypt-proxy-android_arm-${PACKAGE_VERSION:-dev}.zip android-arm

go clean
env CC=aarch64-linux-android21-clang CXX=aarch64-linux-android21-clang++ CGO_ENABLED=1 GOOS=android GOARCH=arm64 go build -mod vendor -ldflags="-s -w"
mkdir android-arm64
ln dnscrypt-proxy android-arm64/
cp ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt android-arm64/
zip -9 -r dnscrypt-proxy-android_arm64-${PACKAGE_VERSION:-dev}.zip android-arm64

go clean
env CC=i686-linux-android19-clang CXX=i686-linux-android19-clang++ CGO_ENABLED=1 GOOS=android GOARCH=386 go build -mod vendor -ldflags="-s -w"
mkdir android-i386
ln dnscrypt-proxy android-i386/
cp ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt android-i386/
zip -9 -r dnscrypt-proxy-android_i386-${PACKAGE_VERSION:-dev}.zip android-i386

go clean
env CC=x86_64-linux-android21-clang CXX=x86_64-linux-android21-clang++ CGO_ENABLED=1 GOOS=android GOARCH=amd64 go build -mod vendor -ldflags="-s -w"
mkdir android-x86_64
ln dnscrypt-proxy android-x86_64/
cp ../LICENSE example-dnscrypt-proxy.toml localhost.pem example-*.txt android-x86_64/
zip -9 -r dnscrypt-proxy-android_x86_64-${PACKAGE_VERSION:-dev}.zip android-x86_64

# Done

ls -l dnscrypt-proxy-*.tar.gz dnscrypt-proxy-*.zip
