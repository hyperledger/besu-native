use banderwagon::{CanonicalDeserialize, Element, Fr};
use verkle_trie::proof::{ExtPresent};
use std::collections::BTreeSet;
use jni::sys::jbyteArray;
use jni::sys::jobjectArray;
use jni::JNIEnv;

pub fn bytes32_to_element(bytes: [u8; 32]) -> Element {
    Element::from_bytes(&bytes).unwrap()
}

pub fn bytes32_to_scalar(mut bytes: [u8; 32]) -> Fr {
    bytes.reverse();
    CanonicalDeserialize::deserialize_compressed(&bytes[..]).unwrap()
}


pub fn byte_to_depth_extension_present(value: u8) -> (ExtPresent, u8) {
    let ext_status = value & 3;
    let ext_status = match ext_status {
        0 => ExtPresent::None,
        1 => ExtPresent::DifferentStem,
        2 => ExtPresent::Present,
        x => panic!("unexpected ext status number {} ", x),
    };
    let depth = value >> 3;
    (ext_status, depth)
}

pub fn jobjectarray_to_vec<T, F>(env: &JNIEnv, array: jobjectArray, mut converter: F) -> Vec<T>
where
    F: FnMut([u8; 32]) -> T,
{
    (0..env.get_array_length(array).unwrap() as i32)
        .map(|i| get_array(env, array, i))
        .map(converter)
        .collect()
}

pub fn convert_byte_array_to_fixed_array(env: &JNIEnv, byte_array: jbyteArray) -> [u8; 32] {
    let bytes = env.convert_byte_array(byte_array).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

pub fn get_array(env: &JNIEnv, array: jobjectArray, index: i32) -> [u8; 32]{
   let obj = env.get_object_array_element(array, index).unwrap();
   let bytes = env.convert_byte_array(obj.into_inner()).unwrap();
   let mut elt = [0u8; 32];
   elt.copy_from_slice(&bytes);
   return elt;
}

pub fn get_optional_array(env: &JNIEnv, array: jobjectArray, index: i32) -> Option<[u8; 32]> {
    let obj_result = env.get_object_array_element(array, index);
    if let Ok(obj) = obj_result {
        if obj.is_null() {
            return None;
        }
        let bytes_result = env.convert_byte_array(obj.into_inner());
        if let Ok(bytes) = bytes_result {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return Some(arr);
            }
        }
    }
    None
}

pub fn convert_to_btree_set(env: &JNIEnv, array: jobjectArray) -> BTreeSet<[u8; 31]> {
    let num_element = env.get_array_length(array).unwrap();
    let mut set = BTreeSet::new();
    for i in 0..num_element {
        let array_obj = env.get_object_array_element(array, i).unwrap();
        let array_bytes = env.convert_byte_array(array_obj.into_inner()).unwrap();
        let mut arr = [0u8; 31];
        arr.copy_from_slice(&array_bytes);
        set.insert(arr);
    }
    set
}