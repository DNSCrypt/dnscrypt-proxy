#!/bin/bash

PACKAGE_VERSION="$1"

cd dnscrypt-proxy || exit 1


# setup the environment
#######################
sudo apt-get update -y
sudo apt-get install -y wget wine dotnet-sdk-6.0
sudo dpkg --add-architecture i386 && sudo apt-get update && sudo apt-get install -y wine32

sudo apt-get install -y unzip 

export WINEPREFIX=$HOME/.wine32
export WINEARCH=win32
export WINEDEBUG=-all

wget https://dl.winehq.org/wine/wine-mono/8.1.0/wine-mono-8.1.0-x86.msi 
WINEPREFIX="$HOME/.wine32" WINEARCH=win32 wineboot --init 
WINEPREFIX="$HOME/.wine32" WINEARCH=win32 wine msiexec /i wine-mono-8.1.0-x86.msi 

mkdir $HOME/.wine32/drive_c/temp 
mkdir -p $HOME/.wine/drive_c/temp 
wget https://github.com/wixtoolset/wix3/releases/download/wix3112rtm/wix311-binaries.zip -nv -O wix.zip 

unzip wix.zip -d $HOME/wix 
rm -f wix.zip

builddir=$(pwd)
srcdir=$(cd ..;pwd)
version=$PACKAGE_VERSION

cd $HOME/wix


ln -s $builddir $HOME/wix/build
ln -s $srcdir/contrib/msi $HOME/wix/wixproj
echo "builddir: $builddir"

# build the msi's
#################
for arch in x64 x86
do
  binpath="win32"
  if [[ "$arch" == "x64" ]]; then
    binpath="win64"
  fi

  echo $arch

  wine candle.exe -dVersion=$version -dPlatform=$arch -dPath=build\\$binpath -arch $arch wixproj\\dnscrypt.wxs -out build\\dnscrypt-$arch.wixobj
  wine light.exe -out build\\dnscrypt-proxy-$arch-$version.msi build\\dnscrypt-$arch.wixobj  -sval

done

cd $builddir
