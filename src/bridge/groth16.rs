
use std::collections::HashMap;
use crate::chunk::test_utils::read_map_from_file;
use crate::groth16::g16;
use crate::treepp::*;
use crate::chunk;
use ark_bn254::{Bn254, Fr};
use ark_ff::Field;
use crate::signatures::wots::{wots160, wots256};

pub type WotsPublicKeys = g16::PublicKeys;
pub type WotsSecretKeys = Vec<u8>;
pub type VerifyingKey = ark_groth16::VerifyingKey<Bn254>;
pub type Proof = g16::Proof;
pub type PublicInputs = g16::PublicInputs;
pub type Assertions = g16::Assertions;
pub type WotsSignatures = g16::Signatures;

pub enum WotsSignature {
    Sig256(wots256::Signature),
    Sig160(wots160::Signature),
}


pub fn kickoff_bitcom_lock(
    wots_pk: &WotsPublicKeys, 
    _vk: &VerifyingKey,
) -> Vec<(u32,Script)> {
    // TODO: Split into two parts for kickoff and assert
    generate_bitcommitments(wots_pk)
}

pub fn kickoff_bitcom_witness(
    proof: Proof,
    public_inputs: PublicInputs,
    wots_sk: &WotsSecretKeys,
    vk: &VerifyingKey,
)  -> Vec<Vec<u8>> {
    // TODO
    Vec::new()
}   

pub fn assert_bitcom_lock(
    wots_pk: &WotsPublicKeys, 
    _vk: &ark_groth16::VerifyingKey<Bn254>,
) -> Vec<(u32,Script)> {
    // TODO: Split into two parts for kickoff and assert
    generate_bitcommitments(wots_pk)
}

pub fn assert_bitcom_witness(
    proof: Proof,
    public_inputs: PublicInputs,
    wots_sk: &WotsSecretKeys,
    vk: &VerifyingKey,
) -> Vec<Vec<u8>> {
    // TODO
    Vec::new()
}

pub fn disprove_witness(
    _index: u32,
    hint_script: Script,
) -> Vec<Vec<u8>> {
    hint_script_to_witness(hint_script)
}

pub fn hint_script_to_witness(hint_script: Script) -> Vec<Vec<u8>> {
    let mut witness = Vec::new();
    let res = execute_script(hint_script);
    let stack = res.final_stack;
    for i in 0..stack.len() {
        witness.push(stack.get(i));
    }
    witness
}

pub fn sig_to_witness(
    wots_sig: WotsSignature,
) -> Vec<Vec<u8>> {
    let mut res = Vec::new();
    match wots_sig {
        WotsSignature::Sig160(sig) => {
            for (s, d) in sig {
                res.push(s.to_vec());
                res.push(vec![d]);
            }
        },
        WotsSignature::Sig256(sig) => {
            for (s, d) in sig {
                res.push(s.to_vec());
                res.push(vec![d]);
            }
        }
    }
    res
}

pub fn generate_assert_tapscripts(
    vk: &VerifyingKey, 
    wots_pk: WotsPublicKeys, 
    write_to_file: bool,
    file_prefix: &str,
) -> Vec<Script> {
    let ops_scripts = chunk::api::api_compile(vk);
    let taps = chunk::api::generate_tapscripts(wots_pk, &ops_scripts);
    if write_to_file {
        let mut script_cache = HashMap::new();
        for i in 0..taps.len() {
            script_cache.insert(i as u32, vec![taps[i].clone()]);
        }
        chunk::test_utils::write_scripts_to_separate_files(script_cache, file_prefix);
    }
    taps
}   

pub fn generate_signed_assertions(
    proof: Proof,
    public_inputs: PublicInputs,
    wots_sk: &WotsSecretKeys,
    vk: &VerifyingKey,
    write_to_file: bool,
    file_prefix: &str,
) -> WotsSignatures {
    let assn = gene_assertions(proof, public_inputs, vk);
    let sigs = sign_assertions(wots_sk, assn);
    
    if write_to_file {
        let mut index = 0;
        for ss in sigs.0 {
            let mut s_map: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
            let mut v: Vec<Vec<u8>> = Vec::new();
            for (s, d) in ss {
                v.push(s.to_vec());
                v.push(vec![d]);
            }
            s_map.insert(index, v);
            chunk::test_utils::write_map_to_file(&s_map, &format!("chunker_data/{file_prefix}_{index}.json")).expect("fail to write signed assertions");
            index += 1;
        }
        for ss in sigs.1 {
            let mut s_map: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
            let mut v: Vec<Vec<u8>> = Vec::new();
            for (s, d) in ss {
                v.push(s.to_vec());
                v.push(vec![d]);
            }
            s_map.insert(index, v);
            chunk::test_utils::write_map_to_file(&s_map, &format!("chunker_data/{file_prefix}_{index}.json")).expect("fail to write signed assertions");
            index += 1;
        }
        for ss in sigs.2 {
            let mut s_map: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
            let mut v: Vec<Vec<u8>> = Vec::new();
            for (s, d) in ss {
                v.push(s.to_vec());
                v.push(vec![d]);
            }
            s_map.insert(index, v);
            chunk::test_utils::write_map_to_file(&s_map, &format!("chunker_data/{file_prefix}_{index}.json")).expect("fail to write signed assertions");
            index += 1;
        }
    }
    sigs
}

pub fn gene_assertions(
    proof: Proof,
    public_inputs: PublicInputs,
    vk: &VerifyingKey,
) -> Assertions {
    chunk::api::generate_assertions(proof, public_inputs.to_vec(), vk)
}

pub fn sign_assertions(
    wots_sk: &WotsSecretKeys,
    asserttions: Assertions,
) -> WotsSignatures {
    let (ps, fs, hs) = (asserttions.0, asserttions.1, asserttions.2);
    let secret = String::from_utf8(wots_sk.clone()).unwrap();

    let mut psig: Vec<wots256::Signature> = vec![];
    for i in 0..ps.len() {
        let psi = wots256::get_signature(&format!("{secret}{:04x}", i), &ps[i]);
        psig.push(psi);
    }
    let psig: [wots256::Signature; g16::N_VERIFIER_PUBLIC_INPUTS] = psig.try_into().unwrap();

    let mut fsig: Vec<wots256::Signature> = vec![];
    for i in 0..fs.len() {
        let fsi = wots256::get_signature(&format!("{secret}{:04x}", g16::N_VERIFIER_PUBLIC_INPUTS + i), &fs[i]);
        fsig.push(fsi);
    }
    let fsig: [wots256::Signature; g16::N_VERIFIER_FQS] = fsig.try_into().unwrap();

    let mut hsig: Vec<wots160::Signature> = vec![];
    for i in 0..hs.len() {
        let hsi =
            wots160::get_signature(&format!("{secret}{:04x}", g16::N_VERIFIER_PUBLIC_INPUTS + fs.len() + i), &hs[i]);
        hsig.push(hsi);
    }
    let hsig: [wots160::Signature; g16::N_VERIFIER_HASHES] = hsig.try_into().unwrap();

    (psig, fsig, hsig)
}


pub fn corrupt_signed_assertions(
    wots_sk: &WotsSecretKeys,
    signed_assertions: &mut WotsSignatures,
    index: usize,
) { 
    assert!(index < (g16::N_VERIFIER_PUBLIC_INPUTS + g16::N_VERIFIER_FQS + g16::N_VERIFIER_HASHES), "index exceed limit");
    let secret = String::from_utf8(wots_sk.clone()).unwrap();
    if index < g16::N_VERIFIER_PUBLIC_INPUTS {
        let scramble: [u8; 32] = [0xfu8; 32];
        let corrupt_sig = wots256::get_signature(&format!("{secret}{:04x}", index), &scramble);
        let i = index;
        signed_assertions.0[i] = corrupt_sig;
    } else if index < (g16::N_VERIFIER_PUBLIC_INPUTS + g16::N_VERIFIER_FQS) {
        let scramble: [u8; 32] = [0xfu8; 32];
        let corrupt_sig = wots256::get_signature(&format!("{secret}{:04x}", index), &scramble);
        let i = index - g16::N_VERIFIER_PUBLIC_INPUTS;
        signed_assertions.1[i] = corrupt_sig;
    } else {
        let scramble: [u8; 20] = [0xfu8; 20];
        let corrupt_sig = wots160::get_signature(&format!("{secret}{:04x}", index), &scramble);
        let i = index - g16::N_VERIFIER_PUBLIC_INPUTS - g16::N_VERIFIER_FQS;
        signed_assertions.2[i] = corrupt_sig;
    }   
}

pub fn validate_assertions(
    vk: &VerifyingKey,
    signed_asserts: WotsSignatures,
    inpubkeys: WotsPublicKeys,
) -> Option<(usize, Script)> {
    chunk::api::validate_assertions(vk, signed_asserts, inpubkeys)
}   

pub fn generate_bitcommitments(
    wots_pk: &WotsPublicKeys, 
) -> Vec<(u32,Script)> {
    let mut pubkeys: HashMap<u32, chunk::wots::WOTSPubKey> = HashMap::new();
    for i in 0..wots_pk.0.len() {
        pubkeys.insert(i as u32, chunk::wots::WOTSPubKey::P256(wots_pk.0[i]));
    }
    let len = pubkeys.len();
    for i in 0..wots_pk.1.len() {
        pubkeys.insert((len + i) as u32, chunk::wots::WOTSPubKey::P256(wots_pk.1[i]));
    }
    let len = pubkeys.len();
    for i in 0..wots_pk.2.len() {
        pubkeys.insert((len + i) as u32, chunk::wots::WOTSPubKey::P160(wots_pk.2[i]));
    }
    chunk::compile::compile(
        chunk::compile::Vkey {
            q2: ark_bn254::G2Affine::identity(),
            q3: ark_bn254::G2Affine::identity(),
            p3vk: vec![],
            p1q1: ark_bn254::Fq12::ONE,
            vky0: ark_bn254::G1Affine::identity(),
        },
        &pubkeys,
        true,
    )
}

pub fn generate_wots_keys_from_secrets(secret: &str) -> (WotsPublicKeys, WotsSecretKeys) {
    (
        chunk::api::mock_pubkeys(secret),
        secret.as_bytes().to_vec(),
    )
}

pub fn load_assert_tapscripts_from_file(start_index: usize, end_index: usize, file_prefix: &str) -> Vec<Script> {
    let mut taps = vec![];
    for index in start_index..(end_index+1) {
        let read = chunk::test_utils::read_scripts_from_file(&format!("chunker_data/{file_prefix}_{index}.json"));
        let read_scr = read.get(&(index as u32)).unwrap();
        assert_eq!(read_scr.len(), 1);
        let tap_node = read_scr[0].clone();
        taps.push(tap_node);
    }
    taps
}

pub fn load_all_signed_assertions_from_file(
    file_prefix: &str,
) -> WotsSignatures {
    let mut psig = vec![];
    let (min, max) = (0, g16::N_VERIFIER_PUBLIC_INPUTS);
    for i in min..max {
        let s = load_signed_assertions_from_file(file_prefix, i as u32);
        let sig = if let WotsSignature::Sig256(sig) = s { 
            sig 
        } else {
            panic!("invalid wots signature")
        };
        psig.push(sig);
    }
    let psig: [wots256::Signature; g16::N_VERIFIER_PUBLIC_INPUTS] = psig.try_into().unwrap();

    let mut fsig = vec![];
    let (min, max) = (max, max + g16::N_VERIFIER_FQS);
    for i in min..max {
        let s = load_signed_assertions_from_file(file_prefix, i as u32);
        let sig = if let WotsSignature::Sig256(sig) = s { 
            sig 
        } else {
            panic!("invalid wots signature")
        };
        fsig.push(sig);
    }
    let fsig: [wots256::Signature; g16::N_VERIFIER_FQS] = fsig.try_into().unwrap();

    let mut hsig = vec![];
    let (min, max) = (max, max + g16::N_VERIFIER_HASHES);
    for i in min..max {
        let s = load_signed_assertions_from_file(file_prefix, i as u32);
        let sig = if let WotsSignature::Sig160(sig) = s { 
            sig 
        } else {
            panic!("invalid wots signature")
        };
        hsig.push(sig);
    }
    let hsig: [wots160::Signature; g16::N_VERIFIER_HASHES] = hsig.try_into().unwrap();

    let res = (psig, fsig, hsig);
    res
}

pub fn load_signed_assertions_from_file(
    file_prefix: &str,
    index: u32,
) -> WotsSignature {
    let file_name = format!("chunker_data/{file_prefix}_{index}.json");
    let res = chunk::test_utils::read_map_from_file(&file_name)
        .expect(&format!("fail to read assertion from {file_name}"));
    let v = res.get(&index).unwrap();

    const W256_LEN: u32 = wots256::N_DIGITS * 2;
    const W160_LEN: u32 = wots160::N_DIGITS * 2;

    match v.len() as u32 {
        W256_LEN => { 
            let mut res: Vec<([u8; 20], u8)> = Vec::new();
            let sig_len = W256_LEN / 2;
            for i in 0..sig_len {
                res.push((
                    v[(2*i) as usize].clone().try_into().unwrap(), 
                    v[(2*i+1) as usize][0]));
            }
            WotsSignature::Sig256(res.try_into().unwrap())
        }
        W160_LEN => { 
            let mut res: Vec<([u8; 20], u8)> = Vec::new();
            let sig_len = W160_LEN / 2;
            for i in 0..sig_len {
                res.push((
                    v[(2*i) as usize].clone().try_into().unwrap(), 
                    v[(2*i+1) as usize][0]));
            }
            WotsSignature::Sig160(res.try_into().unwrap())

        }
        _ => panic!("Invalid wots siganture length")
    }
}

pub fn load_proof_from_file(filename: &str) -> (VerifyingKey, Proof, PublicInputs) {
    use ark_serialize::CanonicalDeserialize;
    use ark_serialize::Compress;
    use ark_serialize::Validate;
    fn tmp_fr_deserialization(v: Vec<u8>) -> Fr {
        use ark_ff::PrimeField;
        use ark_ff::BigInt;
    
        let mut arr = [0u64; 4];
        for (i, chunk) in v.chunks(8).enumerate() {
            arr[i] = u64::from_le_bytes(chunk.try_into().expect("Invalid fr length"));
        }
        Fr::from_bigint(BigInt(arr)).unwrap()
    }
    

    let read = read_map_from_file(filename).expect(&format!("fail to read proof file: {filename}"));
    let vk_vec = read.get(&0).unwrap();
    let proof_vec = read.get(&1).unwrap();
    let pubin_vec = read.get(&2).unwrap();

    let vk = VerifyingKey::deserialize_with_mode(vk_vec[0].as_slice(), Compress::Yes, Validate::Yes).unwrap();
    let proof = Proof::deserialize_with_mode(proof_vec[0].as_slice(), Compress::Yes, Validate::Yes).unwrap();

    let mut pubin= vec![];
    for i in 0..pubin_vec.len() {
            let f = tmp_fr_deserialization(pubin_vec[i].clone());
            pubin.push(f);
    }

    (vk, proof, pubin.try_into().unwrap())
}

fn serialize_proof(vk: VerifyingKey, proof: Proof, pubin: PublicInputs) -> HashMap<u32, Vec<Vec<u8>>> {
    fn tmp_fr_serialization(f: Fr) -> Vec<u8> {
        use ark_ff::PrimeField;
        use ark_ff::BigInt;
    
        let f_big = match f.into_bigint() { BigInt(x) => x };
        let mut res = Vec::with_capacity(f_big.len() * 8);
        for &num in f_big.iter() {
            res.extend_from_slice(&num.to_le_bytes());
        }
        res
    }   
    

    use ark_serialize::CanonicalSerialize;
    use ark_serialize::Compress;

    let mut vk_sered = vec![0; vk.serialized_size(Compress::Yes)];
    vk.serialize_with_mode(&mut vk_sered[..], Compress::Yes).expect("fail to serialize vk");

    let mut proof_sered = vec![0; proof.serialized_size(Compress::Yes)];
    proof.serialize_with_mode(&mut proof_sered[..], Compress::Yes).expect("fail to serialize proof");

    let mut public_inputs_sered = Vec::new();
    for f in pubin {
        let f_sered = tmp_fr_serialization(f);
        public_inputs_sered.push(f_sered);
    }

    let mut res_map: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
    res_map.insert(0, vec![vk_sered]);
    res_map.insert(1, vec![proof_sered]);
    res_map.insert(2, public_inputs_sered);

    res_map
}

pub const TEST_SECRET: &str = "a138982ce17ac813d505a5b40b665d404e9528e7";

#[test]
pub fn test_compile_tapnodes() {
    let _ = std::fs::create_dir("chunker_data/compile");
    let (vk, _, _) = load_proof_from_file("chunker_data/dummy_proof.json");
    let ops_scripts = chunk::api::api_compile(&vk);
    for i in 0..ops_scripts.len() {
        let mut script_cache = HashMap::new();
        script_cache.insert(i as u32, vec![ops_scripts[i].clone()]);
        chunk::test_utils::write_scripts_to_file(script_cache, &format!("chunker_data/compile/tapnode_{i}.json"));
    }
}

#[test] 
pub fn test_gene_taps() {
    fn run() {
        println!("load scripts from file");
        let mut op_scripts = vec![];
        for index in 0..g16::N_TAPLEAVES {
            let read = chunk::test_utils::read_scripts_from_file(&format!("chunker_data/compile/tapnode_{index}.json"));
            let read_scr = read.get(&(index as u32)).unwrap();
            assert_eq!(read_scr.len(), 1);
            let tap_node = read_scr[0].clone();
            op_scripts.push(tap_node);
        }
        let ops_scripts: [Script; g16::N_TAPLEAVES] = op_scripts.try_into().unwrap(); 
        println!("done");
    
        let _ = std::fs::create_dir("chunker_data/tapscripts");
        let (wots_pk, _) = generate_wots_keys_from_secrets(TEST_SECRET);
        let taps = chunk::api::generate_tapscripts(wots_pk, &ops_scripts);
        for i in 0..taps.len() {
            let mut script_cache = HashMap::new();
            script_cache.insert(i as u32, vec![taps[i].clone()]);
            chunk::test_utils::write_scripts_to_file(script_cache, &format!("chunker_data/tapscripts/tapscript_{i}.json"));
        }
    }

    use std::thread;
    const STACK_SIZE: usize = 4 * 1024 * 1024;

    let t = thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(run)
        .unwrap();

    t.join().unwrap();
}


#[test]
pub fn test_gene_sigs() {
    let _ = std::fs::create_dir("chunker_data/signed_assertions");
    let (vk, proof, pubin) = load_proof_from_file("chunker_data/dummy_proof.json");
    let (_, wots_sk) = generate_wots_keys_from_secrets(TEST_SECRET);
    generate_signed_assertions(proof, pubin, &wots_sk, &vk, true, "signed_assertions/signed_assertion");
}

#[test]
pub fn test_validate_assertions() {
    let (vk, _, _) = load_proof_from_file("chunker_data/dummy_proof.json");
    let (wots_pk, _) = generate_wots_keys_from_secrets(TEST_SECRET);
    let signed_assertions = load_all_signed_assertions_from_file("signed_assertions/signed_assertion");
    validate_assertions(&vk, signed_assertions, wots_pk);
}

#[test]
pub fn test_disprove_invalid_assertions() {
    fn run() {
        let (vk, _, _) = load_proof_from_file("chunker_data/dummy_proof.json");
        let (wots_pk, wots_sk) = generate_wots_keys_from_secrets(TEST_SECRET);
        let mut signed_assertions = load_all_signed_assertions_from_file("signed_assertions/signed_assertion");
        let mut failure = Vec::new();
        let mut success_num = 0;
        for i in 0..(g16::N_VERIFIER_PUBLIC_INPUTS + g16::N_VERIFIER_FQS + g16::N_VERIFIER_HASHES) {
            println!("\ntest disprove assertion_{i}:");
            corrupt_signed_assertions(&wots_sk, &mut signed_assertions, i);
            
            let res = validate_assertions(&vk, signed_assertions, wots_pk);

            assert!(res.is_some(), "unexpected validate assertions result");
            let (leaf_index, hint_script) = res.unwrap();
            let lock_script = load_assert_tapscripts_from_file(leaf_index, leaf_index+1, "tapscripts/tapscript");
            let lock_script = lock_script[0].clone();
            let scr = script!(
                {hint_script}
                {lock_script}
            );
            let res = execute_script(scr);
            let success = if res.success {"succcess"} else {"fail"} ;
            if !res.success { failure.push(i) } else {success_num+=1};
            println!("result: {success}");
        }
        print!("\x1B[2J\x1B[1;1H");
        println!("\n--------test_result---------");
        println!("{success_num} ok, {:?} fail",failure.len());
        dbg!(failure);
        println!("----------------");
    }

    use std::thread;
    const STACK_SIZE: usize = 32 * 1024 * 1024;
    let t = thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(run)
        .unwrap();
    t.join().unwrap();
}


