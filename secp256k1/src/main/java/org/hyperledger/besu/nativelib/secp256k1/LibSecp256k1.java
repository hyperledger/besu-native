/*
 * Copyright ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
package org.hyperledger.besu.nativelib.secp256k1;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

import com.sun.jna.Callback;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.Structure.FieldOrder;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;

public class LibSecp256k1 implements Library {

  private static final int SECP256K1_FLAGS_TYPE_CONTEXT = 1;
  private static final int SECP256K1_FLAGS_TYPE_COMPRESSION = 1 << 1;
  private static final int SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = 1 << 8;
  private static final int SECP256K1_FLAGS_BIT_CONTEXT_SIGN = 1 << 9;
  private static final int SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY = 1 << 10;
  private static final int SECP256K1_FLAGS_BIT_COMPRESSION = 1 << 8;

  public static final int SECP256K1_CONTEXT_VERIFY =
      SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY;
  public static final int SECP256K1_CONTEXT_SIGN =
      SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN;
  public static final int SECP256K1_CONTEXT_DECLASSIFY =
      SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY;
  public static final int SECP256K1_CONTEXT_NONE = SECP256K1_FLAGS_TYPE_CONTEXT;

  public static final int SECP256K1_EC_COMPRESSED =
      SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION;
  public static final int SECP256K1_EC_UNCOMPRESSED = SECP256K1_FLAGS_TYPE_COMPRESSION;

  public static final PointerByReference CONTEXT = createContext();

  private static PointerByReference createContext() {
    try {
      Native.register(LibSecp256k1.class, "secp256k1");
      final PointerByReference context =
          secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
      if (Boolean.parseBoolean(System.getProperty("secp256k1.randomize", "true"))) {
        // randomization requested or not explicitly disabled
        byte[] seed = new byte[32];
        SecureRandom.getInstanceStrong().nextBytes(seed);
        if (secp256k1_context_randomize(context, seed) != 1) {
          // there was an error, don't preserve the context
          return null;
        }
      }
      return context;
    } catch (final Throwable t) {
      return null;
    }
  }

  /**
   * A pointer to a function to deterministically generate a nonce
   *
   * <p>Except for test cases, this function should compute some cryptographic hash of the message,
   * the algorithm, the key and the attempt.
   */
  public interface secp256k1_nonce_function extends Callback {

    /**
     * @param nonce32 (output) Pointer to a 32-byte array to be filled by the function.
     * @param msg32 The 32-byte message hash being verified (will not be NULL).
     * @param key32 Pointer to a 32-byte secret key (will not be NULL)
     * @param algo16 Pointer to a 16-byte array describing the signature * algorithm (will be NULL
     *     for ECDSA for compatibility).
     * @param data Arbitrary data pointer that is passed through.
     * @param attempt How many iterations we have tried to find a nonce. This will almost always be
     *     0, but different attempt values are required to result in a different nonce.
     * @return 1 if a nonce was successfully generated. 0 will cause signing to fail.
     */
    int apply(
        Pointer nonce32, Pointer msg32, Pointer key32, Pointer algo16, Pointer data, int attempt);
  }

  /**
   * Opaque data structure that holds a parsed and valid public key.
   *
   * <p>The exact representation of data inside is implementation defined and not guaranteed to be
   * portable between different platforms or versions. It is however guaranteed to be 64 bytes in
   * size, and can be safely copied/moved. If you need to convert to a format suitable for storage,
   * transmission, or comparison, use secp256k1_ec_pubkey_serialize and secp256k1_ec_pubkey_parse.
   */
  @FieldOrder({"data"})
  public static class secp256k1_pubkey extends Structure {
    public byte[] data = new byte[64];
  }

  /**
   * Opaque data structured that holds a parsed ECDSA signature.
   *
   * <p>The exact representation of data inside is implementation defined and not guaranteed to be
   * portable between different platforms or versions. It is however guaranteed to be 64 bytes in
   * size, and can be safely copied/moved. If you need to convert to a format suitable for storage,
   * transmission, or comparison, use the secp256k1_ecdsa_signature_serialize_* and
   * secp256k1_ecdsa_signature_parse_* functions.
   */
  @FieldOrder({"data"})
  public static class secp256k1_ecdsa_signature extends Structure {
    public byte[] data = new byte[64];
  }

  /**
   * Opaque data structured that holds a parsed ECDSA signature, supporting pubkey recovery.
   *
   * <p>The exact representation of data inside is implementation defined and not guaranteed to be
   * portable between different platforms or versions. It is however guaranteed to be 65 bytes in
   * size, and can be safely copied/moved. If you need to convert to a format suitable for storage
   * or transmission, use the secp256k1_ecdsa_signature_serialize_* and
   * secp256k1_ecdsa_signature_parse_* functions.
   *
   * <p>Furthermore, it is guaranteed that identical signatures (including their recoverability)
   * will have identical representation, so they can be memcmp'ed.
   */
  @FieldOrder({"data"})
  public static class secp256k1_ecdsa_recoverable_signature extends Structure {
    public byte[] data = new byte[65];
  }

  /**
   * Create a secp256k1 context object (in dynamically allocated memory).
   *
   * <p>This function uses malloc to allocate memory. It is guaranteed that malloc is called at most
   * once for every call of this function. If you need to avoid dynamic memory allocation entirely,
   * see the functions in secp256k1_preallocated.h.
   *
   * <p>See also secp256k1_context_randomize.
   *
   * @param flags which parts of the context to initialize.
   * @return a newly created context object.
   */
  public static native PointerByReference secp256k1_context_create(final int flags);

  /**
   * Parse a variable-length public key into the pubkey object.
   *
   * <p>This function supports parsing compressed (33 bytes, header byte 0x02 or 0x03), uncompressed
   * (65 bytes, header byte 0x04), or hybrid (65 bytes, header byte 0x06 or 0x07) format public
   * keys.
   *
   * @param ctx a secp256k1 context object.
   * @param pubkey (output) pointer to a pubkey object. If 1 is returned, it is set to a parsed
   *     version of input. If not, its value is undefined.
   * @param input pointer to a serialized public key
   * @param inputlen length of the array pointed to by input
   * @return 1 if the public key was fully valid. 0 if the public key could not be parsed or is
   *     invalid.
   */
  public static native int secp256k1_ec_pubkey_parse(
      final PointerByReference ctx,
      final secp256k1_pubkey pubkey,
      final byte[] input,
      final long inputlen);

  /**
   * Serialize a pubkey object into a serialized byte sequence.
   *
   * @param ctx a secp256k1 context object.
   * @param output (output) a pointer to a 65-byte (if compressed==0) or 33-byte (if compressed==1)
   *     byte array to place the serialized key in.
   * @param outputlen (input/output) a pointer to an integer which is initially set to the size of
   *     output, and is overwritten with the written size.
   * @param pubkey a pointer to a secp256k1_pubkey containing an initialized public key.
   * @param flags SECP256K1_EC_COMPRESSED if serialization should be in compressed format, otherwise
   *     SECP256K1_EC_UNCOMPRESSED.
   * @return 1 always.
   */
  public static native int secp256k1_ec_pubkey_serialize(
      final PointerByReference ctx,
      final ByteBuffer output,
      final LongByReference outputlen,
      final secp256k1_pubkey pubkey,
      final int flags);

  /**
   * Parse an ECDSA signature in compact (64 bytes) format.
   *
   * <p>The signature must consist of a 32-byte big endian R value, followed by a 32-byte big endian
   * S value. If R or S fall outside of [0..order-1], the encoding is invalid. R and S with value 0
   * are allowed in the encoding.
   *
   * <p>After the call, sig will always be initialized. If parsing failed or R or S are zero, the
   * resulting sig value is guaranteed to fail validation for any message and public key.
   *
   * @param ctx a secp256k1 context object.
   * @param sig (output) a pointer to a signature object
   * @param input64 a pointer to the 64-byte array to parse
   * @return 1 when the signature could be parsed, 0 otherwise.
   */
  public static native int secp256k1_ecdsa_signature_parse_compact(
      final PointerByReference ctx, final secp256k1_ecdsa_signature sig, final byte[] input64);

  /**
   * Convert a signature to a normalized lower-S form.
   *
   * <p>With ECDSA a third-party can forge a second distinct signature of the same
   * message, given a single initial signature, but without knowing the key. This
   * is done by negating the S value modulo the order of the curve, 'flipping'
   * the sign of the random point R which is not included in the signature.
   *
   * <p>Forgery of the same message isn't universally problematic, but in systems
   * where message malleability or uniqueness of signatures is important this can
   * cause issues. This forgery can be blocked by all verifiers forcing signers
   * to use a normalized form.
   *
   * <p>The lower-S form reduces the size of signatures slightly on average when
   * variable length encodings (such as DER) are used and is cheap to verify,
   * making it a good choice. Security of always using lower-S is assured because
   * anyone can trivially modify a signature after the fact to enforce this
   * property anyway.
   *
   * <p>The lower S value is always between 0x1 and
   * 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
   * inclusive.
   *
   * <p>No other forms of ECDSA malleability are known and none seem likely, but
   * there is no formal proof that ECDSA, even with this additional restriction,
   * is free of other malleability. Commonly used serialization schemes will also
   * accept various non-unique encodings, so care should be taken when this
   * property is required for an application.
   *
   * <p>The secp256k1_ecdsa_sign function will by default create signatures in the
   * lower-S form, and secp256k1_ecdsa_verify will not accept others. In case
   * signatures come from a system that cannot enforce this property,
   * secp256k1_ecdsa_signature_normalize must be called before verification.
   *
   * @param ctx a secp256k1 context object.
   * @param sigout (output) a pointer to a signature to fill with the normalized form,
   *                        or copy if the input was already normalized. (can be NULL if
   *                        you're only interested in whether the input was already
   *                        normalized).
   * @param sigin (input) a pointer to a signature to check/normalize (cannot be NULL,
   *                        can be identical to sigout)
   * @return 1 if sigin was not normalized, 0 if it already was.
   */
  public static native int secp256k1_ecdsa_signature_normalize(final PointerByReference ctx, final secp256k1_ecdsa_signature sigout, final secp256k1_ecdsa_signature sigin);

  /**
   * Verify an ECDSA signature.
   *
   * <p>To avoid accepting malleable signatures, only ECDSA signatures in lower-S form are accepted.
   *
   * <p>If you need to accept ECDSA signatures from sources that do not obey this rule, apply
   * secp256k1_ecdsa_signature_normalize to the signature prior to validation, but be aware that
   * doing so results in malleable signatures.
   *
   * <p>For details, see the comments for that function.
   *
   * @param ctx a secp256k1 context object, initialized for verification.
   * @param sig the signature being verified (cannot be NULL)
   * @param msg32 the 32-byte message hash being verified (cannot be NULL)
   * @param pubkey pointer to an initialized public key to verify with (cannot be NULL)
   * @return 1 if it is a correct signature, 0 if it is an incorrect or unparseable signature.
   */
  public static native int secp256k1_ecdsa_verify(
      final PointerByReference ctx,
      final secp256k1_ecdsa_signature sig,
      final byte[] msg32,
      final secp256k1_pubkey pubkey);

  /**
   * Compute the public key for a secret key.
   *
   * @param ctx pointer to a context object, initialized for signing (cannot be NULL)
   * @param pubkey (output) pointer to the created public key (cannot be NULL)
   * @param seckey pointer to a 32-byte private key (cannot be NULL)
   * @return 1 if secret was valid, public key stores, 0 if secret was invalid, try again.
   */
  public static native int secp256k1_ec_pubkey_create(
      final PointerByReference ctx, final secp256k1_pubkey pubkey, final byte[] seckey);

  /**
   * Updates the context randomization to protect against side-channel leakage. While secp256k1 code
   * is written to be constant-time no matter what secret values are, it's possible that a future
   * compiler may output code which isn't, and also that the CPU may not emit the same radio
   * frequencies or draw the same amount power for all values.
   *
   * <p>This function provides a seed which is combined into the blinding value: that blinding value
   * is added before each multiplication (and removed afterwards) so that it does not affect
   * function results, but shields against attacks which rely on any input-dependent behaviour.
   *
   * <p>This function has currently an effect only on contexts initialized for signing because
   * randomization is currently used only for signing. However, this is not guaranteed and may
   * change in the future. It is safe to call this function on contexts not initialized for signing;
   * then it will have no effect and return 1.
   *
   * <p>You should call this after secp256k1_context_create or secp256k1_context_clone (and
   * secp256k1_context_preallocated_create or secp256k1_context_clone, resp.), and you may call this
   * repeatedly afterwards.
   *
   * @param ctx pointer to a context object (cannot be NULL)
   * @param seed32 pointer to a 32-byte random seed (NULL resets to initial state)
   * @return Returns 1 if randomization successfully updated or nothing to randomize or 0 if an
   *     error occured
   */
  public static native int secp256k1_context_randomize(
      final PointerByReference ctx, final byte[] seed32);

  /**
   * Parse a compact ECDSA signature (64 bytes + recovery id).
   *
   * @param ctx a secp256k1 context object
   * @param sig (output) a pointer to a signature object
   * @param input64 a pointer to a 64-byte compact signature
   * @param recid the recovery id (0, 1, 2 or 3)
   * @return 1 when the signature could be parsed, 0 otherwise
   */
  public static native int secp256k1_ecdsa_recoverable_signature_parse_compact(
      final PointerByReference ctx,
      final secp256k1_ecdsa_recoverable_signature sig,
      final byte[] input64,
      final int recid);

  /**
   * Serialize an ECDSA signature in compact format (64 bytes + recovery id).
   *
   * @param ctx a secp256k1 context object
   * @param output64 (output) a pointer to a 64-byte array of the compact signature (cannot be NULL)
   * @param recid (output) a pointer to an integer to hold the recovery id (can be NULL).
   * @param sig a pointer to an initialized signature object (cannot be NULL)
   */
  public static native void secp256k1_ecdsa_recoverable_signature_serialize_compact(
      final PointerByReference ctx,
      final ByteBuffer output64,
      final IntByReference recid,
      final secp256k1_ecdsa_recoverable_signature sig);

  /**
   * Create a recoverable ECDSA signature.
   *
   * @param ctx pointer to a context object, initialized for signing (cannot be NULL)
   * @param sig (output) pointer to an array where the signature will be placed (cannot be NULL)
   * @param msg32 the 32-byte message hash being signed (cannot be NULL)
   * @param seckey pointer to a 32-byte secret key (cannot be NULL)
   * @param noncefp pointer to a nonce generation function. If NULL,
   *     secp256k1_nonce_function_default is used
   * @param ndata pointer to arbitrary data used by the nonce generation function (can be NULL)
   * @return 1 if signature created, 0 if the nonce generation function failed or the private key
   *     was invalid.
   */
  public static native int secp256k1_ecdsa_sign_recoverable(
      final PointerByReference ctx,
      final secp256k1_ecdsa_recoverable_signature sig,
      final byte[] msg32,
      final byte[] seckey,
      final secp256k1_nonce_function noncefp,
      final Pointer ndata);

  /**
   * Recover an ECDSA public key from a signature.
   *
   * @param ctx pointer to a context object, initialized for verification (cannot be NULL)
   * @param pubkey (output) pointer to the recovered public key (cannot be NULL)
   * @param sig pointer to initialized signature that supports pubkey recovery (cannot be NULL)
   * @param msg32 the 32-byte message hash assumed to be signed (cannot be NULL)
   * @return 1 if public key successfully recovered (which guarantees a correct signature), 0
   *     otherwise.
   */
  public static native int secp256k1_ecdsa_recover(
      final PointerByReference ctx,
      final secp256k1_pubkey pubkey,
      final secp256k1_ecdsa_recoverable_signature sig,
      final byte[] msg32);
}
