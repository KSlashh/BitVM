use crate::connectors::base::generate_default_tx_in;
use crate::disprove_scripts::{push_preimage_to_stack, PubinDisproveScriptType};
use crate::{error::Error, transactions::base::Input};
use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use bitcoin::taproot::LeafVersion;
use bitcoin::{taproot::TaprootSpendInfo, ScriptBuf, TxIn};
use bitvm::chunk::api::type_conversion_utils::script_to_witness;
use bitvm::chunk::api::validate_assertions_lit;
use bitvm::chunk::api::{
    type_conversion_utils::{utils_signatures_from_raw_witnesses, RawWitness},
    NUM_TAPS,
};
use bitvm::treepp::*;

pub fn validate_assert(
    raw_assert_witness: Vec<RawWitness>,
    ack_preimages: Vec<Vec<u8>>, // preimages length should match the number of hashes, use empty vec for unknown preimages
    pubin_disprove_scripts: &[(PubinDisproveScriptType, ScriptBuf)],
    vk: &VerifyingKey<Bn254>,
    proof_disprove_scripts: &[ScriptBuf; NUM_TAPS],
) -> Option<(RawWitness, ScriptBuf)> {
    let wots_sigs = utils_signatures_from_raw_witnesses(&raw_assert_witness);
    for (scr_type, scr) in pubin_disprove_scripts.iter() {
        match scr_type {
            PubinDisproveScriptType::Constant(index) => {
                let wit = raw_assert_witness[*index].clone();
                let wit_scr = script! {
                    { wit.clone() }
                };
                let full_scr = wit_scr.clone().push_script(scr.clone());
                let exec_result = execute_script(full_scr);
                if exec_result.success {
                    return Some((script_to_witness(wit_scr), scr.clone()));
                }
            }
            PubinDisproveScriptType::Hashlock(index, _) => {
                let pubin_wit = raw_assert_witness[*index].clone();
                let wit_scr = script! {
                    { pubin_wit.clone() }
                    { push_preimage_to_stack(&ack_preimages) }
                };
                let full_scr = wit_scr.clone().push_script(scr.clone());
                let exec_result = execute_script(full_scr);
                if exec_result.success {
                    return Some((script_to_witness(wit_scr), scr.clone()));
                }
            }
        }
    }
    match validate_assertions_lit(vk, wots_sigs, proof_disprove_scripts) {
        Some((index, wit)) => Some((
            script_to_witness(wit),
            proof_disprove_scripts[index].clone(),
        )),
        None => None,
    }
}

pub fn disprove(
    connector_e_taproot_spend_info: &TaprootSpendInfo,
    connector_e_input: &Input,
    input_script_witness: RawWitness,
    input_lock_script: ScriptBuf,
) -> Result<TxIn, Error> {
    let mut txin = generate_default_tx_in(connector_e_input);
    // push witness
    input_script_witness
        .into_iter()
        .for_each(|x| txin.witness.push(x));
    // push script and control block
    let prevout_leaf = (input_lock_script, LeafVersion::TapScript);
    let control_block = match connector_e_taproot_spend_info.control_block(&prevout_leaf) {
        Some(c) => c,
        None => {
            return Err(Error::Other(
                "Unable to generate control block for disprove txin",
            ))
        }
    };
    txin.witness.push(prevout_leaf.0.to_bytes());
    txin.witness.push(control_block.serialize());
    Ok(txin)
}
