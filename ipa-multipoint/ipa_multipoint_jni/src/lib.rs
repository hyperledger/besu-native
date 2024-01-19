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

use ipa_multipoint::crs::CRS;
use ipa_multipoint::committer::DefaultCommitter;

use banderwagon::*;
use ipa_multipoint::committer::Committer;

use jni::JNIEnv;
use jni::objects::JClass;
use jni::sys::jbyteArray;
use jni::objects::JObject;
use jni::objects::GlobalRef;
use verkle_spec::hash64;
use verkle_spec::H256;

use jni::sys::jlong;


pub const VERKLE_NODE_WIDTH: usize = 256;

pub struct ExtendedCommitter {
    inner: DefaultCommitter,
    callback: GlobalRef,
}

impl ExtendedCommitter {
    fn new(points: &[Element], callback: GlobalRef) -> Self {
        let inner = DefaultCommitter::new(points);
        Self { inner, callback }
    }
}

/// # Safety
///
/// This is safe to call as long as the pointer is valid.
#[no_mangle]
pub unsafe extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_committerPointer(
    env: JNIEnv,
    _class: JClass,
    callback: JObject,
) -> jlong {
    let global_ref = env.new_global_ref(callback).unwrap();
    let committer = ExtendedCommitter::new(&CRS::default().G, global_ref);

    Box::into_raw(Box::new(committer)) as jlong
}


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

    let mut address32 = [0u8; 32];

    address32.copy_from_slice(&input[0..32]);

    let mut trie_index= [0u8; 32];

    trie_index.copy_from_slice(&input[32..64]);
    trie_index.reverse(); // reverse for little endian per specs

    let base_hash = hash_addr_int(&address32, &trie_index);

    let result = base_hash.as_fixed_bytes();
    
    env.byte_array_from_slice(result).unwrap()
}

// Helper function to hash an address and an integer taken from rust-verkle/verkle-specs.
pub(crate) fn hash_addr_int(addr: &[u8; 32], integer: &[u8; 32]) -> H256 {

    let address_bytes = addr;

    let integer_bytes = integer;
    let mut hash_input = [0u8; 64];
    let (first_half, second_half) = hash_input.split_at_mut(32);

    // Copy address and index into slice, then hash it
    first_half.copy_from_slice(address_bytes);
    second_half.copy_from_slice(integer_bytes);

    hash64(hash_input)
}

/// # Safety
///
/// This is safe to call as long as the pointer is valid.
/// 
/// Commit receives a list of 32 byte scalars and returns a 32 byte scalar
/// Scalar is actually the map_to_field(commitment) because we want to reuse the commitment in parent node.
/// This is ported from rust-verkle.
#[no_mangle]
pub unsafe extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_commit(env: JNIEnv,
                                                                                                 _class: JClass<'_>,
                                                                                                 input: jbyteArray,
                                                                                                 committer_pointer: jlong)
                                                                                                 -> jbyteArray {
    // Input should be a multiple of 32-be-bytes.
    let inp = env.convert_byte_array(input).expect("Cannot convert jbyteArray to rust array");
    let len = inp.len();
    if len % 32 != 0 {
        env.throw_new("java/lang/IllegalArgumentException", "Invalid input length. Should be a multiple of 32-bytes.")
           .expect("Failed to throw exception");
        return std::ptr::null_mut(); // Return null pointer to indicate an error
    }    
    let n_scalars = len / 32;
    if n_scalars > 256 {
        env.throw_new("java/lang/IllegalArgumentException", "Invalid input length. Should be at most 256 elements of 32-bytes.")
           .expect("Failed to throw exception");
        return std::ptr::null_mut(); // Return null pointer to indicate an error
    }    

    // Each 32-be-bytes are interpreted as field elements.
    let mut scalars: Vec<Fr> = Vec::with_capacity(n_scalars);
    for b in inp.chunks(32) {
        scalars.push(Fr::from_be_bytes_mod_order(b));
    }


    let committer = &mut *(committer_pointer as *mut ExtendedCommitter);

    let result = committer.inner.commit_lagrange(&scalars.as_slice()[0..n_scalars]);

    // Serializing via x/y in projective coordinates, to int and to scalars.
    let scalar = group_to_field(&result);
    let mut scalar_bytes = [0u8; 32];
    scalar.serialize_uncompressed(&mut scalar_bytes[..]).expect("could not serialise Fr into a 32 byte array");
    scalar_bytes.reverse();

    env.byte_array_from_slice(&scalar_bytes).expect("Couldn't convert to byte array")
}


/// # Safety
///
/// This is safe to call as long as the pointer is valid.
/// 
/// commitRoot receives a list of 32 byte scalars and returns a 32 byte commitment.to_bytes()
/// This is ported from rust-verkle.
#[no_mangle]
pub unsafe extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_commitRoot(env: JNIEnv,
                                                                                                 _class: JClass<'_>,
                                                                                                 input: jbyteArray,
                                                                                                 committer_pointer: jlong)
                                                                                                 -> jbyteArray {
    // Input should be a multiple of 32-be-bytes.
    let inp = env.convert_byte_array(input).expect("Cannot convert jbyteArray to rust array");
    let len = inp.len();
    if len % 32 != 0 {
        env.throw_new("java/lang/IllegalArgumentException", "Invalid input length. Should be a multiple of 32-bytes.")
           .expect("Failed to throw exception");
        return std::ptr::null_mut(); // Return null pointer to indicate an error
    }    
    let n_scalars = len / 32;
    if n_scalars > 256 {
        env.throw_new("java/lang/IllegalArgumentException", "Invalid input length. Should be at most 256 elements of 32-bytes.")
           .expect("Failed to throw exception");
        return std::ptr::null_mut(); // Return null pointer to indicate an error
    }    

    // Each 32-be-bytes are interpreted as field elements.
    let mut scalars: Vec<Fr> = Vec::with_capacity(n_scalars);
    for b in inp.chunks(32) {
        scalars.push(Fr::from_be_bytes_mod_order(b));
    }


    let committer = &mut *(committer_pointer as *mut ExtendedCommitter);

    let result = committer.inner.commit_lagrange(&scalars.as_slice()[0..n_scalars]);

    // Serializing using first affine coordinate
    let commit_bytes = result.to_bytes();

    env.byte_array_from_slice(&commit_bytes).expect("Couldn't convert to byte array")
}


// Note: This is a 2 to 1 map, but the two preimages are identified to be the same
// TODO: Create a document showing that this poses no problems
pub(crate)fn group_to_field(point: &Element) -> Fr {
    let base_field = point.map_to_scalar_field();
    let mut bytes = [0u8; 32];
    base_field
        .serialize_uncompressed(&mut bytes[..])
        .expect("could not serialise point into a 32 byte array");
    Fr::from_le_bytes_mod_order(&bytes)
}
