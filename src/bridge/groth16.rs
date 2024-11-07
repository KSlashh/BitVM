
use std::collections::HashMap;
use crate::groth16::g16;
use crate::treepp::*;
use crate::chunk;
use ark_bn254::Bn254;

pub type WotsPublicKeys = g16::WotsPublicKeys;
pub type WotsSecretKeys = Vec<u8>;
pub type VerifyingKey = ark_groth16::VerifyingKey<Bn254>;
pub type Proof = g16::Proof;

pub fn kickoff_bitcom_lock(
    wots_pk: &WotsPublicKeys, 
    vk: &VerifyingKey,
) -> Script {
    script! {
        // TODO
    }
}

pub fn kickoff_bitcom_witness(
    proof: &Proof,
    wots_sk: &WotsSecretKeys,
    vk: &VerifyingKey,
) {
    // TODO
}   

pub fn assert_bitcom_lock(
    wots_pk: &WotsPublicKeys, 
    vk: &ark_groth16::VerifyingKey<Bn254>,
) -> Script {
    script! {
        // TODO
    }
}

pub fn assert_bitcom_witness(
    proof: &Proof,
    wots_sk: &WotsSecretKeys,
    vk: &VerifyingKey,
) {
    // TODO
}

pub fn generate_assert_tapscripts(
    vk: &VerifyingKey, 
    wots_pk: WotsPublicKeys, 
    write_to_file: bool,
) -> Vec<Script> {
    let ops_scripts = chunk::api::api_compile(vk);
    let taps = chunk::api::generate_tapscripts(wots_pk, &ops_scripts);
    if write_to_file {
        let mut script_cache = HashMap::new();
        for i in 0..taps.len() {
            script_cache.insert(i as u32, vec![taps[i].clone()]);
        }
        chunk::test_utils::write_scripts_to_separate_files(script_cache, "tapnode");
    }
    taps
}   

pub fn load_assert_tapscripts_from_file(start_index: usize, end_index: usize) -> Vec<Script> {
    let mut taps = vec![];
    for index in start_index..(end_index+1) {
        let read = chunk::test_utils::read_scripts_from_file(&format!("chunker_data/tapnode_{index}.json"));
        let read_scr = read.get(&(index as u32)).unwrap();
        assert_eq!(read_scr.len(), 1);
        let tap_node = read_scr[0].clone();
        taps.push(tap_node);
    }
    taps
}

pub fn generate_wots_keys_from_secrets(secret: &str) -> (WotsPublicKeys, WotsSecretKeys) {
    (
        chunk::api::mock_pubkeys(secret),
        secret.as_bytes().to_vec(),
    )
}




