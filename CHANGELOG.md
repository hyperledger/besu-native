# Changelog

# 0.8.4-SNAPSHOT

# 0.8.3

* add support for Mimc on bls12-377 [#132](https://github.com/hyperledger/besu-native/pull/132)
* FIX: javadoc issues [#125](https://github.com/hyperledger/besu-native/pull/125)
* ENH: adds ipa-multipoint library with Pedersen primitives [#123](https://github.com/hyperledger/besu-native/pull/123)
* Bump github.com/consensys/gnark-crypto in /gnark/gnark-jni [#122](https://github.com/hyperledger/besu-native/pull/122)


# 0.8.2

* Add k1 normalize signature method to secp256k1 [#118]](https://github.com/hyperledger/besu-native/pull/118)

# 0.8.1

* Handle incomplete input on modExp correctly [#114]](https://github.com/hyperledger/besu-native/pull/114)

# 0.8.0

* Add mimc/gnark library [#106](https://github.com/hyperledger/besu-native/pull/106)
* Change module names from `native` to `nativelib` [#108](https://github.com/hyperledger/besu-native/pull/108)
* Use Aurora's modexp implementation in arithmetic [#111](https://github.com/hyperledger/besu-native/pull/111)

# 0.7.0

* Add new "arithmetic" library to support basic (but expensive) arithmetic [#98](https://github.com/hyperledger/besu-native/pull/98)

# 0.6.2

* support computing proof with n arguments [#89](https://github.com/hyperledger/besu-native/pull/89)
* Java modules support [#90](https://github.com/hyperledger/besu-native/pull/90)
* Add CodeQL workflow for GitHub code scanning [#92](https://github.com/hyperledger/besu-native/pull/92)

# 0.6.1

* Update to latest jna, use separate build folders per os/arch [#79](https://github.com/hyperledger/besu-native/pull/79)
* Add linux arm64 build of bls12-381 [#81](https://github.com/hyperledger/besu-native/pull/81), [#80](https://github.com/hyperledger/besu-native/pull/80)
* Restrict builds of blake2f to x86-64 [#82](https://github.com/hyperledger/besu-native/pull/82) 

# 0.6.0

* Add native implementation of the Blake2bf compress function for EIP152 [#69](https://github.com/hyperledger/besu-native/pull/69)

# 0.5.0

* Add linux-arm64 native support [#61](https://github.com/hyperledger/besu-native/pull/61)
* Add ipa-multipoint library support [#56](https://github.com/hyperledger/besu-native/pull/56)

## 0.4.3

* Use non-blocking PRNG to generate secp256k1 context [#51](https://github.com/hyperledger/besu-native/pull/51)
* Padding R and S components if smaller than 31 bytes in SECP256R1 keys [#52](https://github.com/hyperledger/besu-native/pull/52)

## 0.4.2

* Fix Besu integration on MacOS [#48](https://github.com/hyperledger/besu-native/pull/48)

## 0.4.1

* Fix native representation of native secp256r1 signatures [#45](https://github.com/hyperledger/besu-native/pull/45)

## 0.4.0

* Added support for secp256r1 via OpenSSL libraries.

## 0.3.0

* Upgraded secp256k1 to commit ac05f61fcf639a15b5101131561620303e4bd808, which
  improves performance by using efficiently-computable endomorphism.
* Add support for MatterLab's EIP196/197 for ECPairings, which are faster than
  the sputnikvm code.

## 0.2.0

* Add support for EIP-2537 (BLS12-381 precompiles ) via MatterLabs library
* Randomize secp256k1 context by default, with java property
  `secp256k1.randomize` escape hatch to disable. In tight testing loop this
  flag should be set to false.

## 0.1.0

* Add support for AltBN128 precompiles via sputnik VM
* Add support for secp256k1 via Bitcoin core library
