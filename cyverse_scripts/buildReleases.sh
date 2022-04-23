#! /bin/bash
rm -rf release
mkdir -p release

VERSION=$(git tag --sort=committerdate | tail -1)
COMMIT_SHA=$(git describe --always --dirty)
BUILD_DATE=$(date -u +%FT%TZ)
LDFLAGS="-s -w -X 'github.com/drakkan/sftpgo/v2/version.commit=${COMMIT_SHA}' -X 'github.com/drakkan/sftpgo/v2/version.date=${BUILD_DATE}'"

mkdir -p release/etc/sftpgo
cp sftpgo.json release/etc/sftpgo/sftpgo.json

mkdir -p release/usr/share/sftpgo
cp -r templates release/usr/share/sftpgo/templates
cp -r static release/usr/share/sftpgo/static
cp -r openapi release/usr/share/sftpgo/openapi

GOOS=linux GOARCH=386 go build -trimpath -ldflags="${LDFLAGS}" -v -o release/sftpgo ./
cd release && tar cvf sftpgo_i386_linux_${VERSION}.tar sftpgo etc usr && cd ..

GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="${LDFLAGS}" -v -o release/sftpgo ./
cd release && tar cvf sftpgo_amd64_linux_${VERSION}.tar sftpgo etc usr && cd ..

GOOS=linux GOARCH=arm go build -trimpath -ldflags="${LDFLAGS}" -v -o release/sftpgo ./
cd release && tar cvf sftpgo_arm_linux_${VERSION}.tar sftpgo etc usr && cd ..

GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="${LDFLAGS}" -v -o release/sftpgo ./
cd release && tar cvf sftpgo_arm64_linux_${VERSION}.tar sftpgo etc usr && cd ..

rm -r release/etc release/usr release/sftpgo