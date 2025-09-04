#!/bin/bash
apt-get update
DEBIAN_FRONTEND=non-interactive apt-get install -y autoconf build-essential libtool automake patchelf curl openjdk-21-jdk git wget cmake
export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java))))
export PATH=$JAVA_HOME/bin:$PATH
wget https://go.dev/dl/go1.24.1.linux-arm64.tar.gz
echo "8df5750ffc0281017fb6070fba450f5d22b600a02081dceef47966ffaf36a3af  go1.24.1.linux-arm64.tar.gz" | sha256sum -c || exit 1
tar -xzf go1.24.1.linux-arm64.tar.gz -C $HOME
export GOPATH=$HOME/.go
mkdir -p $GOPATH
export GOROOT="$HOME/go"
export PATH="$GOROOT/bin":$PATH
export CARGO_HOME="$HOME/.cargo"
curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.89.0
export PATH=$PATH:$CARGO_HOME/bin
git config --global --add safe.directory /home/ubuntu/secp256r1/besu-native-ec
git config --global --add safe.directory /home/ubuntu/secp256r1/besu-native-ec/openssl
/home/ubuntu/build.sh
