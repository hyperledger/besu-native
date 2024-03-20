/* Copyright Besu Contributors 
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
mod parsers;
use parsers::{parse_scalars, parse_indices, parse_commitment, parse_commitments};

use jni::objects::JClass;
use jni::sys::jbyteArray;
use jni::JNIEnv;
use once_cell::sync::Lazy;

use std::convert::TryInto;


// TODO: Use a pointer here instead. This is only being used so that the interface does not get changed.
// TODO: and bindings do not need to be modified.
pub static CONFIG: Lazy<ffi_interface::Context> = Lazy::new(ffi_interface::Context::default);


/// Commit receives a list of 32 byte scalars and returns a 32 byte scalar
/// Scalar is actually the map_to_field(commitment) because we want to reuse the commitment in parent node.
/// This is ported from rust-verkle.
#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_commit(
    env: JNIEnv, _class: JClass<'_>, values: jbyteArray,
) -> jbyteArray {
    let input = match parse_scalars(&env, values) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/IllegalArgumentException", e) 
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let commitment = match ffi_interface::commit_to_scalars(&CONFIG, &input) {
        Ok(v) => v,
        Err(e) => {
            let error_message = format!("Could not commit to scalars: {}", e);
            env.throw_new("java/lang/IllegalArgumentException", &error_message);
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let result = match env.byte_array_from_slice(&commitment) {
        Ok(v) => v,
        Err(_) => {
            env.throw_new("java/lang/IllegalArgumentException",
                          "Couldn't return commitment.")
            .expect("Couldn't convert to byte array");
            return std::ptr::null_mut();
        }
    };
    result
}

#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_commitAsCompressed(
    env: JNIEnv, _class: JClass<'_>, values: jbyteArray
) -> jbyteArray {
    let input = match parse_scalars(&env, values) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/IllegalArgumentException", e) 
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let commitment = match ffi_interface::commit_to_scalars(&CONFIG, &input) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/IllegalArgumentException", format!("{e:?}"))
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let compressed = ffi_interface::serialize_commitment(commitment);
    let result = match env.byte_array_from_slice(&compressed) {
        Ok(v) => v,
        Err(_) => {
            env.throw_new("java/lang/IllegalArgumentException",
                          "Couldn't return commitment.")
            .expect("Couldn't convert to byte array");
            return std::ptr::null_mut();
        }
    };
    result
}

#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_updateSparse(
    env: JNIEnv, _class: JClass<'_>, commitment: jbyteArray, indices: jbyteArray, old_values: jbyteArray, new_values: jbyteArray
) -> jbyteArray {
    let commitment = match parse_commitment(&env, commitment) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/IllegalArgumentException", e) 
               .expect("Failed to throw exception for updateSparse commitment input.");
            return std::ptr::null_mut();
        }
    };
    let pos = match parse_indices(&env, indices) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/IllegalArgumentException", e) 
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let old = match parse_scalars(&env, old_values) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/IllegalArgumentException", e) 
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let old: Vec<ffi_interface::ScalarBytes> = old.chunks_exact(32).map(|x| {
        let mut array = [0u8; 32];
        array.copy_from_slice(x);
        array
    }).collect();
    let new = match parse_scalars(&env, new_values) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/IllegalArgumentException", e) 
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let new: Vec<ffi_interface::ScalarBytes> = new.chunks_exact(32).map(|x| {
        let mut array = [0u8; 32];
        array.copy_from_slice(x);
        array
    }).collect();
    let commitment = match ffi_interface::update_commitment_sparse(&CONFIG, commitment, pos, old, new) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/IllegalArgumentException", format!("{e:?}"))
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let result = match env.byte_array_from_slice(&commitment) {
        Ok(v) => v,
        Err(_) => {
            env.throw_new("java/lang/IllegalArgumentException", "Couldn't return commitment.")
               .expect("Couldn't convert to byte array");
            return std::ptr::null_mut();
        }
    };
    result
}

#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_compress(
    env: JNIEnv, _class: JClass<'_>, commitment: jbyteArray
) -> jbyteArray {

    let commitment = match parse_commitment(&env, commitment) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/IllegalArgumentException", e)
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let compressed = ffi_interface::serialize_commitment(commitment);
    let result = match env.byte_array_from_slice(&compressed) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid commitment output. Couldn't convert to byte array.")
            .expect("Couldn't convert to byte array");
            return std::ptr::null_mut();
        }
    };
    result
}

#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_compressMany(
    env: JNIEnv, _class: JClass<'_>, commitments: jbyteArray
) -> jbyteArray {

    let commitments = match parse_commitments(&env, commitments) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/IllegalArgumentException", e)
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let compressed: Vec<u8> = commitments.chunks_exact(64).flat_map(|x| ffi_interface::serialize_commitment(x.try_into().unwrap())).collect();
    let result = match env.byte_array_from_slice(&compressed) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid commitment output. Couldn't convert to byte array.")
            .expect("Couldn't convert to byte array");
            return std::ptr::null_mut();
        }
    };
   result
}

#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_hash(
    env: JNIEnv, _class: JClass<'_>, commitment: jbyteArray
) -> jbyteArray {
    let commitment = match parse_commitment(&env, commitment) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/IllegalArgumentException", e)
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let hash = ffi_interface::hash_commitment(commitment);
    let result = match env.byte_array_from_slice(&hash) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid commitment output. Couldn't convert to byte array.")
            .expect("Couldn't convert to byte array");
            return std::ptr::null_mut();
        }
    };
    result
}

#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_hashMany(
    env: JNIEnv, _class: JClass<'_>, commitments: jbyteArray
) -> jbyteArray {
    let input = match parse_commitments(&env, commitments) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/IllegalArgumentException", e)
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let input: Vec<ffi_interface::CommitmentBytes> = input.chunks_exact(64).map(|x| {
        let mut array = [0u8; 64];
        array.copy_from_slice(x);
        array
    }).collect();
    let hashes = ffi_interface::hash_commitments(&input);
    let hashes: Vec<u8> = hashes.iter().flat_map(|x| x.iter().copied()).collect();
    let result = match env.byte_array_from_slice(&hashes) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid scalars output. Couldn't convert to byte array.")
            .expect("Couldn't convert to byte array");
            return std::ptr::null_mut();
        }
    };
    result
}
