FROM ubuntu:latest
MAINTAINER dnscrypt-authors

RUN apt-get update && \
    apt-get install -y wget wine dotnet-sdk-6.0 && \
    dpkg --add-architecture i386 && apt-get update && apt-get install -y wine32


ENV WINEPREFIX=/root/.wine32 WINEARCH=win32 WINEDEBUG=-all

RUN wget https://dl.winehq.org/wine/wine-mono/8.1.0/wine-mono-8.1.0-x86.msi && \
    WINEPREFIX="$HOME/.wine32" WINEARCH=win32 wineboot --init && \
    WINEPREFIX="$HOME/.wine32" WINEARCH=win32 wine msiexec /i wine-mono-8.1.0-x86.msi && \
    mkdir $WINEPREFIX/drive_c/temp && \
    apt-get install -y unzip && \
    wget https://github.com/wixtoolset/wix3/releases/download/wix3112rtm/wix311-binaries.zip -nv -O wix.zip && \
    unzip wix.zip -d /wix && \
    rm -f wix.zip

WORKDIR /wix

