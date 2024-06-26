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

mod utils;
use utils::{convert_to_btree_set, get_optional_array, get_array, convert_byte_array_to_fixed_array,jobjectarray_to_vec};
use utils::{byte_to_depth_extension_present,bytes32_to_scalar,bytes32_to_element};

use jni::objects::JClass;
use jni::sys::{jbyteArray, jobjectArray};
use jni::JNIEnv;
use once_cell::sync::Lazy;

use std::convert::TryInto;
use ipa_multipoint::multiproof::{MultiPointProof};
use ipa_multipoint::ipa::{IPAProof};
use verkle_trie::proof::{ExtPresent,VerificationHint, VerkleProof};

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
           let error_message = format!("Could not commit to scalars: {:?}", e);
           env.throw_new("java/lang/IllegalArgumentException", &error_message)
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let result = match env.byte_array_from_slice(&commitment) {
        Ok(v) => v,
        Err(e) => {
            let error_message = format!("Couldn't return commitment.: {:?}", e);
            env.throw_new("java/lang/IllegalArgumentException", &error_message)
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
        Err(e) => {
            let error_message = format!("Couldn't return commitment: {:?}", e);
            env.throw_new("java/lang/IllegalArgumentException", &error_message)
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
        Err(e) => {
            let error_message = format!("Couldn't return commitment: {:?}", e);
            env.throw_new("java/lang/IllegalArgumentException", &error_message)
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
        Err(e) => {
            let error_message = format!("Invalid commitment output. Couldn't convert to byte array: {:?}", e);
            env.throw_new("java/lang/IllegalArgumentException", &error_message)
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
        Err(e) => {
            let error_message = format!("Invalid commitment output. Couldn't convert to byte array: {:?}", e);
            env.throw_new("java/lang/IllegalArgumentException", &error_message)
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
        Err(_e) => {
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
        Err(e) => {
            let error_message = format!("Invalid scalars output. Couldn't convert to byte array: {:?}", e);
            env.throw_new("java/lang/IllegalArgumentException", &error_message)
            .expect("Couldn't convert to byte array");
            return std::ptr::null_mut();
        }
    };
    result

}


#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_verifyPreStateRoot(
    env: JNIEnv, _class: JClass<'_>, stems_keys: jobjectArray,
                                     current_values: jobjectArray ,
                                     commitments_by_path : jobjectArray,
                                     cl : jobjectArray,
                                     cr : jobjectArray,
                                     other_stems : jobjectArray,
                                     d : jbyteArray,
                                     depths_extension_present_stems : jbyteArray,
                                     final_evaluation : jbyteArray,
                                     prestate_root : jbyteArray
) -> bool {

    let num_keys = match env.get_array_length(stems_keys) {
        Ok(len) => len,
        Err(_) => return false,
    };

    let mut formatted_keys: Vec<[u8; 32]> = Vec::new();
    let mut formatted_current_values : Vec<Option<[u8; 32]>> = Vec::new();

    for i in 0..num_keys {
        match get_array(&env, stems_keys, i) {
            Some(key) => formatted_keys.push(key),
            None => return false,
        }
        match get_optional_array(&env, current_values, i) {
            Some(value) => formatted_current_values.push(value),
            None => return false,
        }
    }

    let formatted_commitments = match jobjectarray_to_vec(&env, commitments_by_path, |b| bytes32_to_element(b)) {
            Some(vec) => vec,
            None => return false,
    };

    let formatted_cl = match jobjectarray_to_vec(&env, cl, |b| bytes32_to_element(b)) {
        Some(vec) => vec,
        None => return false,
    };

    let formatted_cr = match jobjectarray_to_vec(&env, cr, |b| bytes32_to_element(b)) {
        Some(vec) => vec,
        None => return false,
    };

    let formatted_d = match convert_byte_array_to_fixed_array(&env, d) {
            Some(arr) => arr,
            None => return false,
    };

    let formatted_final_evaluation = match convert_byte_array_to_fixed_array(&env, final_evaluation) {
        Some(arr) => arr,
        None => return false,
    };

    let scalar_final_evaluation = match bytes32_to_scalar(formatted_final_evaluation) {
            Some(scalar) => scalar,
            None => return false,
    };

    let g_x_comm = match bytes32_to_element(formatted_d) {
        Some(element) => element,
        None => return false,
    };

    let proof = MultiPointProof {
        open_proof: IPAProof {
            L_vec: formatted_cl,
            R_vec: formatted_cr,
            a: scalar_final_evaluation,
        },
        g_x_comm: g_x_comm,
    };

    let depths_bytes = match env.convert_byte_array(depths_extension_present_stems) {
            Ok(bytes) => bytes,
            Err(_) => return false,
    };
    let (formatted_extension_present, depths): (Vec<ExtPresent>, Vec<u8>) = depths_bytes
        .iter()
        .map(|&byte| byte_to_depth_extension_present(byte as u8))
        .unzip();

    let formatted_other_stems = match convert_to_btree_set(&env, other_stems) {
        Some(set) => set,
        None => return false,
    };

    let verkle_proof = VerkleProof {
        verification_hint: VerificationHint {
            depths: depths,
            extension_present: formatted_extension_present,
            diff_stem_no_proof: formatted_other_stems,
        },
        comms_sorted: formatted_commitments,
        proof,
    };

    let prestate_root_bytes = match convert_byte_array_to_fixed_array(&env, prestate_root).and_then(|bytes| bytes32_to_element(bytes)) {
        Some(element) => element,
        None => return false,
    };

    let (bool,_update_hint) = verkle_proof.check(formatted_keys, formatted_current_values, prestate_root_bytes);
    bool
}
