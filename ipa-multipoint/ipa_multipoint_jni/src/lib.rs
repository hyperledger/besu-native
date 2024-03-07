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
use jni::sys::jbyteArray;
use jni::JNIEnv;
use once_cell::sync::Lazy;

// TODO: Use a pointer here instead. This is only being used so that the interface does not get changed.
// TODO: and bindings do not need to be modified.
pub static CONFIG: Lazy<ffi_interface::Context> = Lazy::new(ffi_interface::Context::default);

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

    let commitment = ffi_interface::commit_to_scalars(&CONFIG, &input).unwrap();

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

    let commitment = ffi_interface::commit_to_scalars(&CONFIG, &input).unwrap();
    let hash = ffi_interface::serialize_commitment(commitment);

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

    let (old_commitment_bytes, indexes, old_scalars, new_scalars) =
        match ffi_interface::deserialize_update_commitment_sparse(input) {
            Ok(decomposed_input) => decomposed_input,
            Err(err) => {
                env.throw_new(
                    "java/text/ParseException",
                    format!("Could not deserialize the input, error : {:?}", err),
                )
                .expect("Failed to throw exception");
                return std::ptr::null_mut(); // Return null pointer to indicate an error
            }
        };
    let updated_commitment = ffi_interface::update_commitment_sparse(
        &CONFIG,
        old_commitment_bytes,
        indexes,
        old_scalars,
        new_scalars,
    )
    .unwrap();

    env.byte_array_from_slice(&updated_commitment)
        .expect("Couldn't convert to byte array")
}
