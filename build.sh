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
  OSARCH=${OSTYPE%%[0-9.]*}-`arch`
fi

if [[ "$OSTYPE" == "darwin"* ]];  then
  CORE_COUNT=$(sysctl -n hw.ncpu)
  if [[ "`machine`" == "arm"* ]]; then
    arch_name="aarch64"
    export CFLAGS="-arch arm64"
  else
    arch_name="x86-64"
    export CFLAGS="-arch x86_64"
  fi
  OSARCH="darwin-$arch_name"
fi

# add to path cargo
[ -f $HOME/.cargo/env ] && . $HOME/.cargo/env

# add to path brew
[ -f $HOME/.zprofile ] && . $HOME/.zprofile

build_blake2bf() {

  cat <<EOF
  #############################
  ###### build blake2bf ######
  #############################
EOF

  # This version of arm blake is actually slower than java blake on arm
  if [[ "$OSARCH" == "linux-gnu-aarch64" ]];  then
    return
    #cd "$SCRIPTDIR/blake2bf/arm64"
  else if [[ "$OSARCH" == "darwin-aarch64" ]];  then
    return
    #cd "$SCRIPTDIR/blake2bf/aarch64"
  else
    cd "$SCRIPTDIR/blake2bf/x86_64"
  fi

  # delete old build dir, if exists
  rm -rf "$SCRIPTDIR/blake2bf/build" || true

  if [[ -e makefile ]]; then
    make clean
  fi

  make
  mkdir -p "$SCRIPTDIR/blake2bf/build/${OSARCH}/lib"
  mv libblake2bf.* "$SCRIPTDIR/blake2bf/build/${OSARCH}/lib"
  fi
}

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
    ./configure --prefix="$SCRIPTDIR/secp256k1/build/${OSARCH}" $SECP256K1_BUILD_OPTS && \
    make -j $CORE_COUNT && \
    make -j $CORE_COUNT install
}

build_altbn128() {
  cat <<EOF
  ############################
  ###### build altbn128 ######
  ############################
EOF

  echo "building altbn128 for ${OSARCH}"
  cd "$SCRIPTDIR/altbn128/sputnikvm_altbn128"

  # delete old build dir, if exists
  rm -rf "$SCRIPTDIR/altbn128/build" || true
  mkdir -p "$SCRIPTDIR/altbn128/build/${OSARCH}/lib"

  cargo clean
  if [[ "$OSTYPE" == "darwin"* ]];  then
    lipo_lib "libeth_altbn128" ""
  else
    cargo build --lib --release
  fi
  mkdir -p "$SCRIPTDIR/altbn128/build/${OSARCH}/lib"
  cp target/release/libeth_altbn128.* "$SCRIPTDIR/altbn128/build/${OSARCH}/lib"
}

build_arithmetic() {
  cat <<EOF
  ##############################
  ###### build arithmetic ######
  ##############################
EOF

  cd "$SCRIPTDIR/arithmetic/arithmetic"

  # delete old build dir, if exists
  rm -rf "$SCRIPTDIR/arithmetic/build" || true
  mkdir -p "$SCRIPTDIR/arithmetic/build/lib"

  cargo clean

  if [[ "$OSTYPE" == "darwin"* ]];  then
    lipo_lib "libeth_arithmetic" ""
  else
    cargo build --lib --release
  fi

  mkdir -p "$SCRIPTDIR/arithmetic/build/${OSARCH}/lib"
  cp target/release/libeth_arithmetic.* "$SCRIPTDIR/arithmetic/build/${OSARCH}/lib"
}

build_ipa_multipoint() {
  cat <<EOF
  ##################################
  ###### build ipa_multipoint ######
  ##################################
EOF

  cd "$SCRIPTDIR/ipa-multipoint/ipa_multipoint_jni"

  # delete old build dir, if exists
  rm -rf "$SCRIPTDIR/ipa-multipoint/build" || true
  mkdir -p "$SCRIPTDIR/ipa-multipoint/build/${OSARCH}/lib"

  cargo clean

  if [[ "$OSARCH" == "darwin-x86-64" ]];  then
    cargo build --lib --release --target=x86_64-apple-darwin
    lipo -create \
      -output target/release/libipa_multipoint_jni.dylib \
      -arch x86_64 target/x86_64-apple-darwin/release/libipa_multipoint_jni.dylib
    lipo -info ./target/release/libipa_multipoint_jni.dylib
  elif [[ "$OSARCH" == "darwin-aarch64" ]]; then
    cargo build --lib --release --target=aarch64-apple-darwin
    lipo -create \
      -output target/release/libipa_multipoint_jni.dylib \
      -arch arm64 target/aarch64-apple-darwin/release/libipa_multipoint_jni.dylib
    lipo -info ./target/release/libipa_multipoint_jni.dylib
  else
    cargo build --lib --release
  fi

  mkdir -p "$SCRIPTDIR/ipa-multipoint/build/${OSARCH}/lib"
  cp target/release/libipa_multipoint_jni.* "$SCRIPTDIR/ipa-multipoint/build/${OSARCH}/lib"
}

build_bls12_381() {
  cat <<EOF
  #############################
  ###### build BLS12-381 ######
  #############################
EOF

  echo "building bls12-381 for ${OSARCH}"
  cd "$SCRIPTDIR/bls12-381/updated-eip1962"

  # delete old build dir, if exists
  rm -rf "$SCRIPTDIR/bls12-381/build" || true
  mkdir -p "$SCRIPTDIR/bls12-381/build/${OSARCH}/lib"

  cargo clean
  if [[ "$OSTYPE" == "darwin"* ]];  then
    lipo_lib "libeth_pairings" "--features eip_2357_c_api"
  else
      cargo build --lib --features eip_2357_c_api --release
  fi
  mkdir -p "$SCRIPTDIR/bls12-381/build/${OSARCH}/lib"
  cp target/release/libeth_pairings.* "$SCRIPTDIR/bls12-381/build/${OSARCH}/lib"

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

build_secp256r1() {

  cat <<EOF
  #############################
  ###### build secp256r1 ######
  #############################
EOF

  cd "$SCRIPTDIR/secp256r1/besu-native-ec"

  # delete old build dir, if exists
  rm -rf "$SCRIPTDIR/secp256r1/build" || true
  find . -name *.o -exec rm -rf {} \;

  if [[ "$OSTYPE" == "msys" ]]; then
  	LIBRARY_EXTENSION=dll
  	EXTRA_FLAGS=""
  elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    LIBRARY_EXTENSION=so
    EXTRA_FLAGS=""
  elif [[ "$OSTYPE" == "darwin"* ]]; then
    LIBRARY_EXTENSION=dylib
    EXTRA_FLAGS="no-asm" # avoid assembly because of pipeline error
  fi

  OPENSSL_PLATFORM=""
  if [[ "$OSARCH" == "linux-gnu-aarch64" ]]; then
    OPENSSL_PLATFORM="linux-aarch64"
  fi


  git submodule init
  git submodule update

  cd openssl

  ./Configure $OPENSSL_PLATFORM enable-ec_nistp_64_gcc_128 no-stdio no-ocsp no-nextprotoneg no-module \
              no-legacy no-gost no-engine no-dynamic-engine no-deprecated no-comp \
              no-cmp no-capieng no-ui-console no-tls no-ssl no-dtls no-aria no-bf \
              no-blake2 no-camellia no-cast no-chacha no-cmac no-des no-dh no-dsa \
              no-ecdh no-idea no-md4 no-mdc2 no-ocb no-poly1305 no-rc2 no-rc4 no-rmd160 \
              no-scrypt no-seed no-siphash no-siv no-sm2 no-sm3 no-sm4 no-whirlpool $EXTRA_FLAGS
  make build_generated libcrypto.$LIBRARY_EXTENSION

  cd ../

  ./build.sh

  if [[ "$OSTYPE" == "darwin"* ]]; then
    lipo -info ./release/libbesu_native_ec.dylib
    lipo -info ./release/libbesu_native_ec_crypto.dylib
  fi

  mkdir -p "./release/${OSARCH}"
  echo `pwd`
  cp ./release/libbesu_native_ec* "./release/${OSARCH}/"

}

build_gnark() {
  cat <<EOF
  ############################
  ####### build gnark #######
  ############################
EOF

  cd "$SCRIPTDIR/gnark/gnark-jni"

  # delete old build dir, if exists
  rm -rf "$SCRIPTDIR/gnark/build" || true
  mkdir -p "$SCRIPTDIR/gnark/build/lib"

  if [[ "$OSTYPE" == "msys" ]]; then
    	LIBRARY_EXTENSION=dll
  elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    LIBRARY_EXTENSION=so
  elif [[ "$OSTYPE" == "darwin"* ]]; then
    LIBRARY_EXTENSION=dylib
  fi

  go build -buildmode=c-shared -o libgnark_jni.$LIBRARY_EXTENSION gnark-jni.go
  go build -buildmode=c-shared -o libgnark_eip_2537.$LIBRARY_EXTENSION gnark-eip-2537.go

  mkdir -p "$SCRIPTDIR/gnark/build/${OSARCH}/lib"
  cp libgnark_jni.* "$SCRIPTDIR/gnark/build/${OSARCH}/lib"
  cp libgnark_eip_2537.* "$SCRIPTDIR/gnark/build/${OSARCH}/lib"

}

build_blake2bf
build_secp256k1
build_altbn128
build_arithmetic
build_bls12_381
build_ipa_multipoint
build_secp256r1
build_gnark


build_jars
exit
