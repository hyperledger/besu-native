/*
 * Copyright contributors to Besu.
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

import org.graalvm.nativeimage.ObjectHandle;
import org.graalvm.nativeimage.ObjectHandles;
import org.graalvm.nativeimage.PinnedObject;
import org.graalvm.nativeimage.c.CContext;
import org.graalvm.nativeimage.c.function.CFunction;
import org.graalvm.nativeimage.c.struct.CField;
import org.graalvm.nativeimage.c.struct.CStruct;
import org.graalvm.nativeimage.c.type.CCharPointer;
import org.graalvm.nativeimage.c.type.WordPointer;
import org.graalvm.word.PointerBase;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * GraalVM native-image compatible interface to secp256k1 static library.
 * Provides full secp256k1 API for ECDSA operations including signing, verification,
 * key generation, and public key recovery.
 *
 * <p>This class uses GraalVM's @CFunction annotation to call native C functions
 * directly from statically linked libraries, avoiding the overhead of JNA.
 *
 * <p>The native library required is:
 * <ul>
 *   <li>libsecp256k1.a - Core Bitcoin secp256k1 library with recovery module</li>
 * </ul>
 */
public class LibSecp256k1Graal {

    // Context flags
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

    /** Global context initialized for verification and signing. */
    public static final PointerBase CONTEXT = createContext();

    /** Private constructor to prevent instantiation of utility class. */
    private LibSecp256k1Graal() {}

    /**
     * CContext directives for configuring GraalVM native-image compilation.
     * Specifies header files and libraries required for static linking.
     */
    @CContext(LibSecp256k1Graal.Directives.class)
    public static class Directives implements CContext.Directives {
        @Override
        public List<String> getHeaderFiles() {
            return Arrays.asList(
                "<secp256k1.h>",
                "<secp256k1_recovery.h>"
            );
        }

        @Override
        public List<String> getLibraries() {
            return Collections.singletonList("secp256k1");
        }

        @Override
        public List<String> getLibraryPaths() {
            // Library paths should be configured via native-image build arguments
            return Collections.emptyList();
        }
    }

    /**
     * Opaque data structure that holds a parsed and valid public key (64 bytes).
     */
    @CStruct("secp256k1_pubkey")
    public interface Secp256k1Pubkey extends PointerBase {
        @CField("data")
        CCharPointer data();
    }

    /**
     * Opaque data structure that holds a parsed ECDSA signature (64 bytes).
     */
    @CStruct("secp256k1_ecdsa_signature")
    public interface Secp256k1EcdsaSignature extends PointerBase {
        @CField("data")
        CCharPointer data();
    }

    /**
     * Opaque data structure that holds a parsed ECDSA recoverable signature (65 bytes).
     */
    @CStruct("secp256k1_ecdsa_recoverable_signature")
    public interface Secp256k1EcdsaRecoverableSignature extends PointerBase {
        @CField("data")
        CCharPointer data();
    }

    // ============ Context Management ============

    /**
     * Create a secp256k1 context object.
     *
     * @param flags which parts of the context to initialize
     * @return a newly created context object
     */
    @CFunction(value = "secp256k1_context_create")
    public static native PointerBase secp256k1ContextCreate(int flags);

    /**
     * Updates the context randomization to protect against side-channel leakage.
     *
     * @param ctx pointer to a context object
     * @param seed32 pointer to a 32-byte random seed
     * @return 1 if randomization successfully updated, 0 if an error occurred
     */
    @CFunction(value = "secp256k1_context_randomize")
    public static native int secp256k1ContextRandomize(PointerBase ctx, CCharPointer seed32);

    /**
     * Destroy a secp256k1 context object.
     *
     * @param ctx pointer to a context object
     */
    @CFunction(value = "secp256k1_context_destroy")
    public static native void secp256k1ContextDestroy(PointerBase ctx);

    // ============ Public Key Operations ============

    /**
     * Parse a variable-length public key into the pubkey object.
     *
     * @param ctx a secp256k1 context object
     * @param pubkey pointer to a pubkey object (output)
     * @param input pointer to a serialized public key
     * @param inputlen length of the array pointed to by input
     * @return 1 if the public key was fully valid, 0 otherwise
     */
    @CFunction(value = "secp256k1_ec_pubkey_parse")
    public static native int secp256k1EcPubkeyParse(
        PointerBase ctx,
        Secp256k1Pubkey pubkey,
        CCharPointer input,
        long inputlen);

    /**
     * Serialize a pubkey object into a serialized byte sequence.
     *
     * @param ctx a secp256k1 context object
     * @param output pointer to output array (33 or 65 bytes)
     * @param outputlen pointer to output length (input/output)
     * @param pubkey pointer to a secp256k1_pubkey
     * @param flags SECP256K1_EC_COMPRESSED or SECP256K1_EC_UNCOMPRESSED
     * @return 1 always
     */
    @CFunction(value = "secp256k1_ec_pubkey_serialize")
    public static native int secp256k1EcPubkeySerialize(
        PointerBase ctx,
        CCharPointer output,
        WordPointer outputlen,
        Secp256k1Pubkey pubkey,
        int flags);

    /**
     * Compute the public key for a secret key.
     *
     * @param ctx pointer to a context object
     * @param pubkey pointer to the created public key (output)
     * @param seckey pointer to a 32-byte private key
     * @return 1 if secret was valid, 0 if secret was invalid
     */
    @CFunction(value = "secp256k1_ec_pubkey_create")
    public static native int secp256k1EcPubkeyCreate(
        PointerBase ctx,
        Secp256k1Pubkey pubkey,
        CCharPointer seckey);

    // ============ ECDSA Signature Operations ============

    /**
     * Parse an ECDSA signature in compact (64 bytes) format.
     *
     * @param ctx a secp256k1 context object
     * @param sig pointer to a signature object (output)
     * @param input64 pointer to the 64-byte array to parse
     * @return 1 when the signature could be parsed, 0 otherwise
     */
    @CFunction(value = "secp256k1_ecdsa_signature_parse_compact")
    public static native int secp256k1EcdsaSignatureParseCompact(
        PointerBase ctx,
        Secp256k1EcdsaSignature sig,
        CCharPointer input64);

    /**
     * Convert a signature to a normalized lower-S form.
     *
     * @param ctx a secp256k1 context object
     * @param sigout pointer to output signature (output)
     * @param sigin pointer to input signature
     * @return 1 if sigin was not normalized, 0 if it already was
     */
    @CFunction(value = "secp256k1_ecdsa_signature_normalize")
    public static native int secp256k1EcdsaSignatureNormalize(
        PointerBase ctx,
        Secp256k1EcdsaSignature sigout,
        Secp256k1EcdsaSignature sigin);

    /**
     * Verify an ECDSA signature.
     *
     * @param ctx a secp256k1 context object
     * @param sig the signature being verified
     * @param msg32 the 32-byte message hash being verified
     * @param pubkey pointer to an initialized public key
     * @return 1 if correct signature, 0 if incorrect or unparseable signature
     */
    @CFunction(value = "secp256k1_ecdsa_verify")
    public static native int secp256k1EcdsaVerify(
        PointerBase ctx,
        Secp256k1EcdsaSignature sig,
        CCharPointer msg32,
        Secp256k1Pubkey pubkey);

    // ============ Recoverable Signature Operations ============

    /**
     * Parse a compact ECDSA signature (64 bytes + recovery id).
     *
     * @param ctx a secp256k1 context object
     * @param sig pointer to a signature object (output)
     * @param input64 pointer to a 64-byte compact signature
     * @param recid the recovery id (0, 1, 2 or 3)
     * @return 1 when the signature could be parsed, 0 otherwise
     */
    @CFunction(value = "secp256k1_ecdsa_recoverable_signature_parse_compact")
    public static native int secp256k1EcdsaRecoverableSignatureParseCompact(
        PointerBase ctx,
        Secp256k1EcdsaRecoverableSignature sig,
        CCharPointer input64,
        int recid);

    /**
     * Serialize an ECDSA signature in compact format (64 bytes + recovery id).
     *
     * @param ctx a secp256k1 context object
     * @param output64 pointer to a 64-byte array (output)
     * @param recid pointer to an integer to hold the recovery id (output)
     * @param sig pointer to an initialized signature object
     */
    @CFunction(value = "secp256k1_ecdsa_recoverable_signature_serialize_compact")
    public static native void secp256k1EcdsaRecoverableSignatureSerializeCompact(
        PointerBase ctx,
        CCharPointer output64,
        WordPointer recid,
        Secp256k1EcdsaRecoverableSignature sig);

    /**
     * Recover an ECDSA public key from a signature.
     *
     * @param ctx pointer to a context object
     * @param pubkey pointer to the recovered public key (output)
     * @param sig pointer to initialized signature that supports pubkey recovery
     * @param msg32 the 32-byte message hash assumed to be signed
     * @return 1 if public key successfully recovered, 0 otherwise
     */
    @CFunction(value = "secp256k1_ecdsa_recover")
    public static native int secp256k1EcdsaRecover(
        PointerBase ctx,
        Secp256k1Pubkey pubkey,
        Secp256k1EcdsaRecoverableSignature sig,
        CCharPointer msg32);

    // ============ Helper Methods ============

    /**
     * Create and initialize the global context with randomization.
     *
     * @return initialized context or null if creation failed
     */
    private static PointerBase createContext() {
        try {
            PointerBase context = secp256k1ContextCreate(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
            if (context.isNull()) {
                return null;
            }

            if (Boolean.parseBoolean(System.getProperty("secp256k1.randomize", "true"))) {
                byte[] seed = new byte[32];
                SecureRandom.getInstanceStrong().nextBytes(seed);
                try (PinnedObject pinnedSeed = PinnedObject.create(seed)) {
                    if (secp256k1ContextRandomize(context, pinnedSeed.addressOfArrayElement(0)) != 1) {
                        secp256k1ContextDestroy(context);
                        return null;
                    }
                }
            }
            return context;
        } catch (final Throwable t) {
            return null;
        }
    }

    /**
     * Java-friendly wrapper for public key parsing.
     *
     * @param ctx context object
     * @param pubkey 64-byte array to receive parsed public key
     * @param input serialized public key (33, 65 bytes)
     * @return 1 if valid, 0 otherwise
     */
    public static int ecPubkeyParse(PointerBase ctx, byte[] pubkey, byte[] input) {
        if (pubkey.length != 64) {
            throw new IllegalArgumentException("Public key buffer must be 64 bytes");
        }
        try (PinnedObject pinnedPubkey = PinnedObject.create(pubkey);
             PinnedObject pinnedInput = PinnedObject.create(input)) {
            return secp256k1EcPubkeyParse(
                ctx,
                (Secp256k1Pubkey) pinnedPubkey.addressOfArrayElement(0),
                pinnedInput.addressOfArrayElement(0),
                input.length);
        }
    }

    /**
     * Java-friendly wrapper for public key serialization.
     *
     * @param ctx context object
     * @param pubkey 64-byte internal pubkey representation
     * @param compressed true for compressed (33 bytes), false for uncompressed (65 bytes)
     * @return serialized public key
     */
    public static byte[] ecPubkeySerialize(PointerBase ctx, byte[] pubkey, boolean compressed) {
        if (pubkey.length != 64) {
            throw new IllegalArgumentException("Public key must be 64 bytes");
        }

        int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
        byte[] output = new byte[compressed ? 33 : 65];
        long[] outputLen = new long[] { output.length };

        try (PinnedObject pinnedPubkey = PinnedObject.create(pubkey);
             PinnedObject pinnedOutput = PinnedObject.create(output);
             PinnedObject pinnedOutputLen = PinnedObject.create(outputLen)) {
            secp256k1EcPubkeySerialize(
                ctx,
                pinnedOutput.addressOfArrayElement(0),
                (WordPointer) pinnedOutputLen.addressOfArrayElement(0),
                (Secp256k1Pubkey) pinnedPubkey.addressOfArrayElement(0),
                flags);
        }

        return output;
    }

    /**
     * Java-friendly wrapper for signature verification.
     *
     * @param ctx context object
     * @param signature 64-byte compact signature
     * @param message 32-byte message hash
     * @param pubkey 64-byte internal pubkey representation
     * @return 1 if valid signature, 0 otherwise
     */
    public static int ecdsaVerify(PointerBase ctx, byte[] signature, byte[] message, byte[] pubkey) {
        if (signature.length != 64) {
            throw new IllegalArgumentException("Signature must be 64 bytes");
        }
        if (message.length != 32) {
            throw new IllegalArgumentException("Message must be 32 bytes");
        }
        if (pubkey.length != 64) {
            throw new IllegalArgumentException("Public key must be 64 bytes");
        }

        byte[] sig = new byte[64];
        try (PinnedObject pinnedSig = PinnedObject.create(sig);
             PinnedObject pinnedSignature = PinnedObject.create(signature);
             PinnedObject pinnedMessage = PinnedObject.create(message);
             PinnedObject pinnedPubkey = PinnedObject.create(pubkey)) {

            // Parse the signature
            int parseResult = secp256k1EcdsaSignatureParseCompact(
                ctx,
                (Secp256k1EcdsaSignature) pinnedSig.addressOfArrayElement(0),
                pinnedSignature.addressOfArrayElement(0));

            if (parseResult != 1) {
                return 0;
            }

            // Verify the signature
            return secp256k1EcdsaVerify(
                ctx,
                (Secp256k1EcdsaSignature) pinnedSig.addressOfArrayElement(0),
                pinnedMessage.addressOfArrayElement(0),
                (Secp256k1Pubkey) pinnedPubkey.addressOfArrayElement(0));
        }
    }

    /**
     * Java-friendly wrapper for public key recovery from signature.
     *
     * @param ctx context object
     * @param signature 64-byte compact signature (r || s)
     * @param message 32-byte message hash
     * @param recid recovery id (0 or 1)
     * @return 64-byte recovered public key, or null if recovery failed
     */
    public static byte[] ecdsaRecover(PointerBase ctx, byte[] signature, byte[] message, int recid) {
        if (signature.length != 64) {
            throw new IllegalArgumentException("Signature must be 64 bytes");
        }
        if (message.length != 32) {
            throw new IllegalArgumentException("Message must be 32 bytes");
        }

        byte[] recoverableSig = new byte[65];
        byte[] pubkey = new byte[64];

        try (PinnedObject pinnedRecSig = PinnedObject.create(recoverableSig);
             PinnedObject pinnedSignature = PinnedObject.create(signature);
             PinnedObject pinnedMessage = PinnedObject.create(message);
             PinnedObject pinnedPubkey = PinnedObject.create(pubkey)) {

            // Parse recoverable signature
            int parseResult = secp256k1EcdsaRecoverableSignatureParseCompact(
                ctx,
                (Secp256k1EcdsaRecoverableSignature) pinnedRecSig.addressOfArrayElement(0),
                pinnedSignature.addressOfArrayElement(0),
                recid);

            if (parseResult != 1) {
                return null;
            }

            // Recover public key
            int recoverResult = secp256k1EcdsaRecover(
                ctx,
                (Secp256k1Pubkey) pinnedPubkey.addressOfArrayElement(0),
                (Secp256k1EcdsaRecoverableSignature) pinnedRecSig.addressOfArrayElement(0),
                pinnedMessage.addressOfArrayElement(0));

            return recoverResult == 1 ? pubkey : null;
        }
    }

    /**
     * Java-friendly wrapper for public key creation from private key.
     *
     * @param ctx context object
     * @param seckey 32-byte private key
     * @return 64-byte internal public key representation, or null if invalid
     */
    public static byte[] ecPubkeyCreate(PointerBase ctx, byte[] seckey) {
        if (seckey.length != 32) {
            throw new IllegalArgumentException("Private key must be 32 bytes");
        }

        byte[] pubkey = new byte[64];
        try (PinnedObject pinnedPubkey = PinnedObject.create(pubkey);
             PinnedObject pinnedSeckey = PinnedObject.create(seckey)) {
            int result = secp256k1EcPubkeyCreate(
                ctx,
                (Secp256k1Pubkey) pinnedPubkey.addressOfArrayElement(0),
                pinnedSeckey.addressOfArrayElement(0));

            return result == 1 ? pubkey : null;
        }
    }
}
