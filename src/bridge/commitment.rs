use crate::treepp::*;
use crate::signatures::winternitz::{self, PublicKey, N};
use crate::signatures::winternitz_hash;
use bitcoin::hashes::{hash160, Hash};
use bitcoin::Witness;
// use blake3::hash as blake3;
// use hex::decode as hex_decode;
// use hex::encode as hex_encode;

pub type WPublicKey = Vec<u8>;

pub fn seed_to_secret(seed: &[u8]) -> [u8; 20] {
    let hash = hash160::Hash::hash(&seed);

    hash.to_byte_array()
}

pub fn seed_to_pubkey(seed: &[u8]) -> WPublicKey {
    let secret = seed_to_secret(seed);
    let secret = hex::encode(secret);

    let pubkey = winternitz::generate_public_key(secret.as_str());
    vec_from_winternitz_pub(&pubkey)
}

fn vec_to_winternitz_pub(public_key: &WPublicKey) -> PublicKey {
    assert_eq!(public_key.len(), 20 * N as usize, "invalid winternitz pubkey length, should be {}, got {}", 20*N, public_key.len());

    // Convert Vec<u8> back to [[u8; 20]; 44]
    let pubkey_array: [[u8; 20]; N as usize] = public_key
        .chunks_exact(20)  // Break into chunks of 20 elements
        .map(|chunk| <[u8; 20]>::try_from(chunk).unwrap()) // Convert each chunk to [u8; 20]
        .collect::<Vec<[u8; 20]>>() // Collect into a Vec<[u8; 20]>
        .try_into() // Convert Vec<[u8; 20]> into [[u8; 20]; 44]
        .unwrap();

    pubkey_array
}

fn vec_from_winternitz_pub(public_key: &PublicKey) -> WPublicKey {
    public_key.iter().flatten().cloned().collect()
}

// first n input will be kept in the final stack
pub fn check_sig_dup(public_key: &WPublicKey, input_len: usize, num: usize) -> Script {
    let public_key = vec_to_winternitz_pub(public_key);
    winternitz_hash::check_hash_sig_dup(&public_key, input_len, num)
}

pub fn sign_msg(sec_key: &[u8; 20], message: &[u8]) -> Script {
    let sec_key = hex::encode(sec_key.clone());
    
    winternitz_hash::sign_hash(&sec_key, message)
}

pub fn push_sig_witness(witness: &mut Witness, sec_key: &[u8; 20], message: &[u8]) {
    let sec_key = hex::encode(sec_key.clone());

    winternitz_hash::push_hash_sig_witness(witness, &sec_key, message);
}

mod test {

    use super::{seed_to_pubkey, seed_to_secret, vec_from_winternitz_pub, vec_to_winternitz_pub};

    #[test]
    fn test_key_generation() {
        let seed = [0u8, 0x1, 0x2];
        let seckey = seed_to_secret(&seed);
        let pubkey = seed_to_pubkey(&seed);
        let w_pub = vec_to_winternitz_pub(&pubkey);
        let w_pub_vec = vec_from_winternitz_pub(&w_pub);
        assert_eq!(pubkey, w_pub_vec);
    }
}
