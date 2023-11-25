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
use ark_ff::PrimeField;
use banderwagon::{Fr, multi_scalar_mul, Element};
use ipa_multipoint::crs::CRS;
use verkle_spec::*;
use ark_serialize::CanonicalSerialize;
use verkle_trie::*;


use jni::JNIEnv;
use jni::objects::JClass;
use jni::sys::jbyteArray;


// Copied from rust-verkle: https://github.com/crate-crypto/rust-verkle/blob/581200474327f5d12629ac2e1691eff91f944cec/verkle-trie/src/constants.rs#L12
const PEDERSEN_SEED: &'static [u8] = b"eth_verkle_oct_2021";

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
    let output = env.byte_array_from_slice(result).unwrap();
    output
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

/// Commit receives a list of 32 byte scalars and returns a 32 byte scalar
/// Scalar is actually the map_to_field(commitment) because we want to reuse the commitment in parent node.
/// This is ported from ipa_multipoint.
#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_commit(env: JNIEnv,
                                                                                                 _class: JClass<'_>,
                                                                                                 input: jbyteArray)
                                                                                                 -> jbyteArray {
    // Input should be a multiple of 32-le-bytes.
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

    // Each 32-le-bytes are interpreted as field elements.
    let mut scalars: Vec<Fr> = Vec::with_capacity(n_scalars);
    for b in inp.chunks(32) {
        scalars.push(Fr::from_le_bytes_mod_order(b));
    }

    // Committing all values at once.
    let bases = CRS::new(n_scalars, PEDERSEN_SEED);
    let commit = multi_scalar_mul(&bases.G, &scalars);


    // Serializing using first affine coordinate
    let mut commit_bytes = commit.to_bytes();

    // reverse to little endian for Java
    commit_bytes.reverse();

    return env.byte_array_from_slice(&commit_bytes).expect("Couldn't convert to byte array");
}



/// Expects 32 bytes for the serialized commitment, 32 bytes for the diff between new and old value and 1 byte for the index of the value.
#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_updateCommitment(env: JNIEnv,
                                                                                                 _class: JClass<'_>,
                                                                                                 input: jbyteArray)
                                                                                                 -> jbyteArray {

    let inp = env.convert_byte_array(input).expect("Cannot convert jbyteArray to rust array");

    let total_input = inp.as_slice();
    // Parse the commitment
    let mut commitment_bytes = [0u8; 32];
    commitment_bytes.copy_from_slice(&total_input[0..32]);

    // Parse the new-old value
    let mut new_value_minus_old = [0u8; 32];
    new_value_minus_old.copy_from_slice(&total_input[32..64]);

    // Parse the index of the value
    let index = total_input[64] as usize;

    let new_minus_old_ser = Fr::from_le_bytes_mod_order(&new_value_minus_old);

    let bases = CRS::new(256, PEDERSEN_SEED);

    // reverse to big endian because from_bytes expects big endian
    commitment_bytes.reverse(); 
    let commitment = Element::from_bytes(&commitment_bytes).unwrap();

    // Calculate new commitment
    let new_commitment = commitment + bases.G[index] * new_minus_old_ser;

    let mut result = new_commitment.to_bytes();

    // reverse for little endian for Java calls
    result.reverse();

    let output = env.byte_array_from_slice(&result).expect("Couldn't convert to byte array");

    output
}


// Note: This is a 2 to 1 map, but the two preimages are identified to be the same
// Original authors (https://github.com/kevaundray) comment: TODO: Create a document showing that this poses no problems
pub(crate)fn group_to_field(point: &Element) -> Fr {
    let base_field = point.map_to_field();
    let mut bytes = [0u8; 32];
    base_field
        .serialize(&mut bytes[..])
        .expect("could not serialise point into a 32 byte array");
    Fr::from_le_bytes_mod_order(&bytes)
}


/// GroupToField receives a 32 byte serialized point and returns a 32 byte scalar
#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_groupToField(env: JNIEnv,
                                                                                                 _class: JClass<'_>,
                                                                                                 input: jbyteArray)
                                                                                                 -> jbyteArray {
    let inp = env.convert_byte_array(input).expect("Cannot convert jbyteArray to rust array");

    let mut ser_point_bytes = [0u8; 32];

    ser_point_bytes.copy_from_slice(&inp[0..32]);

    // reverse for little endian for Java calls
    ser_point_bytes.reverse();

    let point = Element::from_bytes(&ser_point_bytes).unwrap();
    let base_field = point.map_to_field();
    let mut bytes = [0u8; 32];
    base_field
        .serialize(&mut bytes[..])
        .expect("could not serialise point into a 32 byte array");
    let scalar = Fr::from_le_bytes_mod_order(&bytes);

    // Serializing using first affine coordinate
    // let commit_bytes = commit.to_bytes();
    let mut scalar_bytes = [0u8; 32];
    // Arkworks works with little endian, so we don't need to reverse
    scalar.serialize(&mut scalar_bytes[..]).expect("could not serialise Fr into a 32 byte array");

    return env.byte_array_from_slice(&scalar_bytes).expect("Couldn't convert to byte array");
}
