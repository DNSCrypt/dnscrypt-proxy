# Scripts and utilities related to building an .msi (Microsoft Standard Installer) file.

## Docker test image for building an MSI locally

```sh
docker build . -f Dockerfile -t ubuntu:dnscrypt-msi
```

## Test building msi files for intel win32 & win64

```sh
./build.sh
```
