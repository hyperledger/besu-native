#!/bin/bash
apt-get update
DEBIAN_FRONTEND=non-interactive apt-get install -y autoconf build-essential libtool automake patchelf curl openjdk-21-jdk git wget
export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java))))
export PATH=$JAVA_HOME/bin:$PATH
wget https://go.dev/dl/go1.24.1.linux-arm64.tar.gz
echo "faec7f7f8ae53fda0f3d408f52182d942cc89ef5b7d3d9f23ff117437d4b2d2f  go1.24.1.linux-arm64.tar.gz" | sha256sum -c || exit 1
tar -xzf go1.24.1.linux-arm64.tar.gz -C $HOME
export GOPATH=$HOME/.go
mkdir -p $GOPATH
export GOROOT="$HOME/go"
export PATH="$GOROOT/bin":$PATH
export CARGO_HOME="$HOME/.cargo"
curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.75.0
export PATH=$PATH:$CARGO_HOME/bin
git config --global --add safe.directory /home/ubuntu/secp256r1/besu-native-ec
git config --global --add safe.directory /home/ubuntu/secp256r1/besu-native-ec/openssl
/home/ubuntu/build.sh
