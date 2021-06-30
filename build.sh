#!/usr/bin/env bash

#############################
######### Variables #########
#############################

# Edit this variable to change the build options for secp256k1
SECP256K1_BUILD_OPTS="--enable-module-recovery"

#############################
####### End Variables #######
#############################

# Initialize external vars - need this to get around unbound variable errors
SKIP_GRADLE="$SKIP_GRADLE"

# Exit script if you try to use an uninitialized variable.
set -o nounset

# Exit script if a statement returns a non-true return value.
set -o errexit

# Use the error status of the first failure, rather than that of the last item in a pipeline.
set -o pipefail

# Resolve the directory that contains this script. We have to jump through a few
# hoops for this because the usual one-liners for this don't work if the script
# is a symlink
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done
SCRIPTDIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"


# Determine core count for parallel make
if [[ "$OSTYPE" == "linux-gnu" ]];  then
  CORE_COUNT=$(nproc)
fi

if [[ "$OSTYPE" == "darwin"* ]];  then
  export CFLAGS="-arch x86_64 -arch arm64"
  CORE_COUNT=$(sysctl -n hw.ncpu)
fi

# add to path cargo
[ -f $HOME/.cargo/env ] && . $HOME/.cargo/env


build_secp256k1() {

  cat <<EOF
  #############################
  ###### build secp256k1 ######
  #############################
EOF

  cd "$SCRIPTDIR/secp256k1/bitcoin-core-secp256k1"

  # delete old build dir, if exists
  rm -rf "$SCRIPTDIR/secp256k1/build" || true

  if [[ -e Makefile ]]; then
    make clean
  fi

  ./autogen.sh && \
    ./configure --prefix="$SCRIPTDIR/secp256k1/build" $SECP256K1_BUILD_OPTS && \
    make -j $CORE_COUNT && \
    make -j $CORE_COUNT install
}

build_altbn128() {
  cat <<EOF
  ############################
  ###### build altbn128 ######
  ############################
EOF

  cd "$SCRIPTDIR/altbn128/sputnikvm_altbn128"

  # delete old build dir, if exists
  rm -rf "$SCRIPTDIR/altbn128/build" || true
  mkdir -p "$SCRIPTDIR/altbn128/build/lib"

  cargo clean

  if [[ "$OSTYPE" == "darwin"* ]];  then
    lipo_lib "libeth_altbn128" ""
  else
    cargo build --lib --release
  fi

  cp target/release/libeth_altbn128.* "$SCRIPTDIR/altbn128/build/lib"
}

build_bls12_381() {
  cat <<EOF
  #############################
  ###### build BLS12-381 ######
  #############################
EOF

  cd "$SCRIPTDIR/bls12-381/matterlabs-eip1962"

  # delete old build dir, if exists
  rm -rf "$SCRIPTDIR/bls12-381/build" || true
  mkdir -p "$SCRIPTDIR/bls12-381/build/lib"

  cargo clean
  if [[ "$OSTYPE" == "darwin"* ]];  then
    lipo_lib "libeth_pairings" "--features eip_2357_c_api"
  else
      cargo build --lib --features eip_2357_c_api --release
  fi
  cp target/release/libeth_pairings.* "$SCRIPTDIR/bls12-381/build/lib"
}

build_jars(){
  ########################
  ###### build jars ######
  ########################

  if [[ "$SKIP_GRADLE" != "true" ]]; then
    cd $SCRIPTDIR
    ./gradlew build
  fi
}


lipo_lib() {
  cat <<EOF
  #################################################
  # multi-arch OSX universal binary build wrapper #
  #################################################
EOF
  LIBNAME=$1
  SWITCHES=$2

  # build both architectures
  cargo build --lib $SWITCHES --release --target=x86_64-apple-darwin
  cargo build --lib $SWITCHES --release --target=aarch64-apple-darwin

  lipo -create \
    -output target/release/$1.dylib \
    -arch x86_64 target/x86_64-apple-darwin/release/$1.dylib \
    -arch arm64 target/aarch64-apple-darwin/release/$1.dylib
}

build_secp256k1
build_altbn128
build_bls12_381
build_jars
exit