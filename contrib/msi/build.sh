#!/bin/bash

version=0.0.0
gitver=$(git describe --tags --always --match="[0-9]*.[0-9]*.[0-9]*" --exclude='*[^0-9.]*')
if [[ "$gitver" != "" ]]; then
 version=$gitver 
fi

# build the image by running: docker build . -f Dockerfile -t ubuntu:dnscrypt-msi
if [[ "$(docker image list -q ubuntu:dnscrypt-msi)" == "" ]]; then
  docker build . -f Dockerfile -t ubuntu:dnscrypt-msi
fi

image=ubuntu:dnscrypt-msi


for arch in x64 x86 
do
  binpath="win32"
  if [[ "$arch" == "x64" ]]; then
    binpath="win64"
  fi
  src=$(cd ../../dnscrypt-proxy/$binpath; pwd)
  echo $src

  docker run --rm -v $(pwd):/wixproj -v $src:/src $image wine candle.exe -dVersion=$version -dPlatform=$arch -dPath=\\src -arch $arch \\wixproj\\dnscrypt.wxs -out \\wixproj\\dnscrypt-$arch.wixobj
  docker run --rm -v $(pwd):/wixproj -v $src:/src $image wine light.exe -out \\wixproj\\dnscrypt-proxy-$arch-$version.msi \\wixproj\\dnscrypt-$arch.wixobj  -sval

done
