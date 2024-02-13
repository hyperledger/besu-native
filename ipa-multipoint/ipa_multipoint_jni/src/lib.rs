/*
 * Copyright Besu Contributors
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
 */

use std::convert::TryInto;

use jni::objects::JClass;
use jni::sys::{jboolean, jbyteArray};
use jni::JNIEnv;
use once_cell::sync::Lazy;

// TODO: Use a pointer here instead. This is only being used so that the interface does not get changed.
// TODO: and bindings do not need to be modified.
pub static CONFIG: Lazy<ffi_interface::Context> = Lazy::new(ffi_interface::Context::default);

/// Pedersen hash receives an address and a trie index and returns a hash calculated this way:
/// H(constant || address_low || address_high || trie_index_low || trie_index_high)
/// where constant = 2 + 256*64
/// address_low = lower 16 bytes of the address interpreted as a little endian integer
/// address_high = higher 16 bytes of the address interpreted as a little endian integer
/// trie_index_low = lower 16 bytes of the trie index
/// trie_index_high = higher 16 bytes of the trie index
/// The result is a 256 bit hash
/// This is ported from rust-verkle/verkle-specs
#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_pedersenHash(
    env: JNIEnv,
    _class: JClass,
    input: jbyteArray,
) -> jbyteArray {
    let input = env.convert_byte_array(input).unwrap();

    let committer = &CONFIG.committer;

    let mut input: [u8; 64] = match input.try_into() {
        Ok(input) => input,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid input length. Should be 64-bytes.",
            )
            .expect("Failed to throw exception");
            return std::ptr::null_mut(); // Return null pointer to indicate an error
        }
    };

    // The tree_index is interpreted as a little endian integer
    // But its given in big endian format.
    // The tree_index is the last 32 bytes of the input,
    // so we use this method to reverse its endian
    fn reverse_last_32_bytes(arr: &mut [u8; 64]) {
        let last_32 = &mut arr[32..];
        last_32.reverse();
    }
    reverse_last_32_bytes(&mut input);

    let hash = ffi_interface::get_tree_key_hash_flat_input(committer, input);
    env.byte_array_from_slice(&hash).unwrap()
}

/// Commit receives a list of 32 byte scalars and returns a 32 byte scalar
/// Scalar is actually the map_to_field(commitment) because we want to reuse the commitment in parent node.
/// This is ported from rust-verkle.
#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_commit(
    env: JNIEnv,
    _class: JClass<'_>,
    input: jbyteArray,
) -> jbyteArray {
    let input = env
        .convert_byte_array(input)
        .expect("Cannot convert jbyteArray to rust array");

    let committer = &CONFIG.committer;

    let commitment = ffi_interface::commit_to_scalars(committer, &input).unwrap();

    env.byte_array_from_slice(&commitment)
        .expect("Couldn't convert to byte array")
}

/// Commit_root receives a list of 32 byte scalars and returns a 32 byte commitment.to_bytes()
/// This is ported from rust-verkle.
#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_commitRoot(
    env: JNIEnv,
    _class: JClass<'_>,
    input: jbyteArray,
) -> jbyteArray {
    let input = env
        .convert_byte_array(input)
        .expect("Cannot convert jbyteArray to rust array");

    let committer = &CONFIG.committer;

    let commitment = ffi_interface::commit_to_scalars(committer, &input).unwrap();
    let hash = ffi_interface::deprecated_serialize_commitment(commitment);

    env.byte_array_from_slice(&hash)
        .expect("Couldn't convert to byte array")
}

#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_groupToField(
    env: JNIEnv,
    _class: JClass<'_>,
    input: jbyteArray,
) -> jbyteArray {
    let commitment = env
        .convert_byte_array(input)
        .expect("Cannot convert jbyteArray to rust array");

    let commitment_bytes = commitment.try_into().unwrap();

    let hash = ffi_interface::hash_commitment(commitment_bytes);

    env.byte_array_from_slice(&hash)
        .expect("Couldn't convert to byte array")
}

/// Update commitment sparse
/// Expects byteArray of fixed 64bytes for the commitment
/// and dynamic tuple (old_scalar(32 bytes), new_scalar(32 bytes), index(1 byte)) in this sequence
/// Bytearray is processed with ffi_interface::deserialize_update_commitment_sparse and sent to ffi_interface::update_commitment_sparse.
/// We get updated commitemnt and return it as 64 bytes.
/// If Commitment is empty we should pass https://github.com/crate-crypto/rust-verkle/blob/bb5af2f2fe9788d49d2896b9614a3125f8227818/ffi_interface/src/lib.rs#L57
#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_updateCommitmentSparse(
    env: JNIEnv,
    _class: JClass<'_>,
    input: jbyteArray,
) -> jbyteArray {
    let input = env
        .convert_byte_array(input)
        .expect("Cannot convert jbyteArray to rust array");

    let committer = &CONFIG.committer;

    let (old_commitment_bytes, indexes, old_scalars, new_scalars) =
        ffi_interface::deserialize_update_commitment_sparse(input);
    let updated_commitment = ffi_interface::update_commitment_sparse(
        committer,
        old_commitment_bytes,
        indexes,
        old_scalars,
        new_scalars,
    )
    .unwrap();

    env.byte_array_from_slice(&updated_commitment)
        .expect("Couldn't convert to byte array")
}

/// Receives a tuple (C_i, f_i(X), z_i, y_i)
/// Where C_i is a commitment to f_i(X) serialized as 32 bytes
/// f_i(X) is the polynomial serialized as 8192 bytes since we have 256 Fr elements each serialized as 32 bytes
/// z_i is index of the point in the polynomial: 1 byte (number from 1 to 256)
/// y_i is the evaluation of the polynomial at z_i i.e value we are opening: 32 bytes
/// Returns a proof serialized as bytes
/// This function assumes that the domain is always 256 values and commitment is 32bytes.
#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_createProof(
    env: JNIEnv,
    _class: JClass<'_>,
    input: jbyteArray,
) -> jbyteArray {
    let input = env
        .convert_byte_array(input)
        .expect("Cannot convert jbyteArray to rust array");

    let result = ffi_interface::create_proof(input);

    env.byte_array_from_slice(&result)
        .expect("Couldn't convert to byte array")
}

/// Receives a proof and a tuple (C_i, z_i, y_i)
/// Where C_i is a commitment to f_i(X) serialized as 64 bytes (uncompressed commitment)
/// z_i is index of the point in the polynomial: 1 byte (number from 1 to 256)
/// y_i is the evaluation of the polynomial at z_i i.e value we are opening: 32 bytes or Fr (scalar field element)
/// Returns true of false.
/// Proof is verified or not.
#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_verifyProof(
    env: JNIEnv,
    _class: JClass<'_>,
    input: jbyteArray,
) -> jboolean {
    let input = env
        .convert_byte_array(input)
        .expect("Cannot convert jbyteArray to rust array");

    let result = ffi_interface::verify_proof(input);

    result as u8
}
