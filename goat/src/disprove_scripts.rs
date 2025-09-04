use bitvm::signatures::{Wots, Wots32};
use bitvm::treepp::*;

pub type PubinValue = [u8; 32];
pub type ChallengeHashType = [u8; 20]; // OP_HASH160

pub enum PubinDisproveScriptType {
    Constant(usize),        // the usize is the index of the public input
    Hashlock(usize, usize), // the first usize is the index of the public input, the second usize is the number of hashes
}

pub fn generate_guest_pubin_commitment(_guest_pubin_num_bytes: usize) -> Script {
    script! {
        // TODO
    }
}

/// Returns a Bitcoin script that verifies a Winternitz signature for the given `wots_pk`
/// and additionally checks that message matches the provided `constant_value`
///
/// ## Precondition
///
/// - The Winternitz signature (compact) is at the stack top.
///
/// ## Postcondition
///
/// - If the signature is invalid: the script fails immediately
/// - If the signature is valid: the script continues to compare msg against `constant_value`
///   - `1` (true): every nibble matches exactly;
///   - `0` (false): at least one nibble does not match.
/// - The comparison process consumes the message, leaving only the final boolean result.
///
pub fn verify_constant_pubin_script(
    wots_pk: &<Wots32 as Wots>::PublicKey,
    constant_value: PubinValue,
) -> Script {
    script! {
        { Wots32::checksig_verify(wots_pk) }
        { 1 }
        for byte in constant_value.to_vec() {
            OP_SWAP
            { byte & 0x0F }
            OP_NUMEQUAL
            OP_BOOLAND

            OP_SWAP
            { byte >> 4 }
            OP_NUMEQUAL
            OP_BOOLAND
        }
    }
}

/// Returns a Bitcoin script that verifies a Winternitz signature for the given `wots_pk`
/// corresponding to a watchtower-included bitmap, and checks the relationship between
/// the bitmap and provided `preimages`.
///
/// ## Precondition
///
/// - The stack top contains the `preimages`.
/// - Below the `preimages` on the stack is the compact Winternitz signature for the watchtower-included bitmap.
///
/// ## Postcondition
///
/// - If the Winternitz signature is invalid: the script fails immediately.
/// - If the signature is valid: the script iterates over each index `i` of the bitmap:
///   - If `watchtower_included_bitmap[i] == 0` and `hash(preimages[i]) == hashes[i]`,
///     the final stack result is `0` (false).
///   - Otherwise, the final stack result is `1` (true).
/// - The comparison consumes the message and preimages from the stack, leaving only the final boolean result.
///
pub fn verify_hashlock_pubin_script(
    wots_pk: <Wots32 as Wots>::PublicKey,
    hashes: Vec<ChallengeHashType>,
) -> Script {
    // assert!(hashes.len() <= TBD);
    fn chunk_count(len: usize, chunk_size: usize) -> usize {
        (len + chunk_size - 1) / chunk_size
    }
    script! {
        for _ in 0..hashes.len() {
            OP_TOALTSTACK
        }
        { Wots32::checksig_verify(&wots_pk) }
        { 1 }
        for chunk in hashes.chunks(4) {
            OP_SWAP
            for i in (1..4).rev() {
                if i >= chunk.len() {
                    { 1 << i } OP_2DUP
                    OP_GREATERTHANOREQUAL
                    OP_IF
                        OP_SUB
                    OP_ELSE
                        OP_DROP
                    OP_ENDIF
                } else {
                    { 1 << i } OP_2DUP
                    OP_GREATERTHANOREQUAL
                    OP_IF
                        OP_SUB OP_FROMALTSTACK OP_DROP
                    OP_ELSE
                        OP_DROP
                        OP_SWAP
                        OP_FROMALTSTACK
                        OP_HASH160
                        { chunk[i].to_vec() }
                        OP_EQUAL
                        OP_NOT
                        OP_BOOLAND
                        OP_SWAP
                    OP_ENDIF
                }
            }
            OP_IF
                OP_FROMALTSTACK OP_DROP
            OP_ELSE
                OP_FROMALTSTACK
                OP_HASH160
                { chunk[0].to_vec() }
                OP_EQUAL
                OP_NOT
                OP_BOOLAND
            OP_ENDIF
        }
        for _ in 0..(64 - chunk_count(hashes.len(), 4)) {
            OP_NIP
        }
    }
}

pub fn push_preimage_to_stack(preimages: &Vec<Vec<u8>>) -> Script {
    script! {
        for chunk in preimages.chunks(4) {
            for i in (0..chunk.len()).rev() {
                { chunk[i].to_vec() }
            }
        }
    }
}

pub fn bits_to_bytes32(bits: &[bool]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = bits.len().min(256);
    for i in 0..len {
        let byte_index = i / 8;
        let bit_index = i % 8;
        if bits[i] {
            out[byte_index] |= 1 << bit_index;
        }
    }
    out
}

pub fn hash160(msg: &Vec<u8>) -> [u8; 20] {
    use bitcoin::hashes::{hash160, Hash};
    hash160::Hash::hash(msg).to_byte_array()
}

#[test]
fn test_hash160() {
    let input = "hello world".as_bytes().to_vec();
    let hash = hash160(&input);
    let hash160_script = script! {
        { input } OP_HASH160
        { hash.to_vec() }
        OP_EQUAL
    };
    let result = execute_script(hash160_script);
    assert!(result.success);
}

#[test]
fn test_verify_constant_pubin_script() {
    use hex::FromHex;
    let secret = Wots32::generate_secret_key();
    let public_key = Wots32::generate_public_key(&secret);
    let correct_msg =
        <[u8; 32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
    let incorrect_msg =
        <[u8; 32]>::from_hex("100102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
    let constant =
        <[u8; 32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();

    let s = script! {
      { Wots32::sign_to_raw_witness(&secret, &correct_msg) }
      { verify_constant_pubin_script(&public_key, constant) }
      { 1 }
      OP_EQUALVERIFY
      OP_TRUE
    };
    let result = execute_script(s);
    dbg! {&result};
    assert!(result.success);
    assert_eq!(result.final_stack.len(), 1);

    let s = script! {
      { Wots32::sign_to_raw_witness(&secret, &incorrect_msg) }
      { verify_constant_pubin_script(&public_key, constant) }
      { 0 }
      OP_EQUALVERIFY
      OP_TRUE
    };
    let result = execute_script(s);
    dbg! {&result};
    assert!(result.success);
    assert_eq!(result.final_stack.len(), 1);
}

#[test]
fn test_verify_hashlock_pubin_script() {
    let secret = Wots32::generate_secret_key();
    let public_key = Wots32::generate_public_key(&secret);
    let hashes_len = 11;
    let mut preimages: Vec<Vec<u8>> = vec![];
    let mut hashes: Vec<[u8; 20]> = vec![];
    for i in 0..hashes_len {
        preimages.push(format!("preimage_{:02x}", i).into_bytes());
        hashes.push(hash160(&preimages[i].clone()));
        // println!("hash {}: {:?}", i, hex::encode(hashes[i].iter().rev().cloned().collect::<Vec<u8>>()));
    }
    fn to_bool_vec(input: &[u8]) -> Vec<bool> {
        input.iter().map(|x| *x != 0).collect()
    }

    {
        // TEST OP_TRUE case: all bitmap=0 indices have preimages that do NOT match the corresponding hashes
        let inclueded = to_bool_vec(&[1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1]);
        let mut input_preimages = vec![vec![]; hashes_len];
        input_preimages[1] = preimages[1].clone();
        let s = script! {
            { Wots32::sign_to_raw_witness(&secret, &bits_to_bytes32(&inclueded)) }
            { push_preimage_to_stack(&input_preimages) }
            { verify_hashlock_pubin_script(public_key.clone(), hashes.clone()) }
            { 1 }
            OP_EQUALVERIFY
            OP_TRUE
        };
        let result = execute_script(s);
        assert!(result.success);
        assert_eq!(result.final_stack.len(), 1);
    }

    {
        // TEST OP_FALSE case 1: at least one bitmap=0 index has a matching preimage hash
        let inclueded = to_bool_vec(&[1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1]);
        let mut input_preimages = vec![vec![]; hashes_len];
        input_preimages[2] = preimages[2].clone();
        let s = script! {
            { Wots32::sign_to_raw_witness(&secret, &bits_to_bytes32(&inclueded)) }
            { push_preimage_to_stack(&input_preimages) }
            { verify_hashlock_pubin_script(public_key.clone(), hashes.clone()) }
            { 0 }
            OP_EQUALVERIFY
            OP_TRUE
        };
        let result = execute_script(s);
        assert!(result.success);
        assert_eq!(result.final_stack.len(), 1);
    }

    {
        // TEST OP_FALSE case 2: bitmap padded with extra bits
        // extra padded bitmap bits should not change the result
        let inclueded = to_bool_vec(&[1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1]);
        let mut input_preimages = vec![vec![]; hashes_len];
        input_preimages[2] = preimages[2].clone();
        let s = script! {
            { Wots32::sign_to_raw_witness(&secret, &bits_to_bytes32(&inclueded)) }
            { push_preimage_to_stack(&input_preimages) }
            { verify_hashlock_pubin_script(public_key.clone(), hashes.clone()) }
            { 0 }
            OP_EQUALVERIFY
            OP_TRUE
        };
        let result = execute_script(s);
        assert!(result.success);
        assert_eq!(result.final_stack.len(), 1);
    }
}
