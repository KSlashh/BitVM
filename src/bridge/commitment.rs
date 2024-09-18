use crate::treepp::*;
use crate::signatures::winternitz::{self, PublicKey, checksum, to_digits, N, N1};
use crate::signatures::winternitz_hash;
use bitcoin::hashes::{hash160, Hash};
use bitcoin::Witness;
use blake3::hash as blake3;
use hex::decode as hex_decode;
use hex::encode as hex_encode;

pub fn seed_to_secret(seed: &[u8]) -> [u8; 20] {
    let hash = hash160::Hash::hash(&seed);

    hash.to_byte_array()
}

pub fn seed_to_pubkey(seed: &[u8]) -> PublicKey {
    let secret = seed_to_secret(seed);
    let secret = hex::encode(secret);

    winternitz::generate_public_key(secret.as_str())
}

// first n input will be kept in the final stack
pub fn check_sig_dup(public_key: &PublicKey, input_len: usize, num: usize) -> Script {

    winternitz_hash::check_hash_sig_dup(public_key, input_len, num)
}

pub fn sign_msg(sec_key: &[u8; 20], message: &[u8]) -> Script {
    let sec_key = hex::encode(sec_key.clone());
    
    winternitz_hash::sign_hash(&sec_key, message)
}

pub fn push_sig_witness(witness: &mut Witness, sec_key: &[u8; 20], message: &[u8]) {
    let secret_key = hex::encode(sec_key.clone());

    winternitz_hash::push_hash_sig_witness(witness, sec_key, message);
}
