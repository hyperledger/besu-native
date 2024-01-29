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
pub static CONFIG: Lazy<ffi_interface::Context> = Lazy::new(|| ffi_interface::Context::default());

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

    let hash = ffi_interface::hash_commitment(commitment);

    env.byte_array_from_slice(&hash)
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
