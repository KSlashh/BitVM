use crate::{bridge::{graphs::base::CALC_ROUND, groth16}, treepp::*};
use bitcoin::{
    hashes::{ripemd160, Hash},
    key::Secp256k1, Witness,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, XOnlyPublicKey,
};
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};

use super::{super::transactions::base::Input, connector::*};
use crate::bridge::commitment::WPublicKey;
use crate::bridge::hash_chain;
use crate::bridge::scripts::generate_pay_to_pubkey_taproot_script;

// Specialized for assert leaves currently.
pub type LockScript = fn(index: u32) -> ScriptBuf;
pub type UnlockWitnessData = Vec<u8>;
pub type UnlockWitness = fn(index: u32) -> UnlockWitnessData;

pub struct DisproveLeaf {
    pub lock: LockScript,
    pub unlock: UnlockWitness,
}

#[derive(Clone)]
pub struct ConnectorC<'a> {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
    pub disprove_tap_scripts: &'a Vec<Script>,
    pub leaf_num: usize,
    pub taproot_address: Option<Address>,
}

impl<'a> ConnectorC<'a> {
    pub fn new(network: Network, operator_taproot_public_key: &XOnlyPublicKey, disprove_tap_scripts: &'a Vec<Script>) -> Self {
        ConnectorC {
            network,
            operator_taproot_public_key: operator_taproot_public_key.clone(),
            disprove_tap_scripts,
            leaf_num: disprove_tap_scripts.len() + 1,
            taproot_address: None,
        }
    }

    pub fn gen_taproot_address(&mut self) -> Address {
        if Option::is_none(&self.taproot_address) {
            let addr: Address = self.generate_taproot_address();
            self.taproot_address = Some(addr);
        }
        self.taproot_address.clone().unwrap()
    }

    pub fn get_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        assert!(leaf_index < self.leaf_num as u32, "Invalid leaf index.");
        if (leaf_index as usize != self.leaf_num) {
            self.disprove_tap_scripts[leaf_index as usize].clone().compile()
        } else {
            script! {
                { self.operator_taproot_public_key }
                OP_CHECKSIG
            }.compile()
        }
    }

    pub fn push_leaf_unlock_witness(&self, witness: &mut Witness, _leaf_index: u32, hint_script: Script) {
        witness.push([0x1]);
        let wit = groth16::hint_script_to_witness(hint_script);
        for w in wit {
            witness.push(w);
        }
    }
}

impl<'a> TaprootConnector for ConnectorC<'a> {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        self.get_taproot_leaf_script(leaf_index)
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        let index = leaf_index.to_usize().unwrap();
        if index >= self.leaf_num {
            panic!("Invalid leaf index.")
        }
        generate_default_tx_in(input)
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        let script_num = self.leaf_num;
        let mut lock_scripts = Vec::with_capacity(script_num);
        for i in 0..script_num {
            lock_scripts.push(self.generate_taproot_leaf_script(i as u32))
        }
        let script_weights = lock_scripts.iter().map(|script| (1, script.clone()));

        TaprootBuilder::with_huffman_tree(script_weights)
            .expect("Unable to add assert leaves")
            .finalize(&Secp256k1::new(), self.operator_taproot_public_key)
            .expect("Unable to finalize assert transaction connector c taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        match self.taproot_address.clone() {
            Some(addr) => addr,
            None => {
                Address::p2tr_tweaked(
                    self.generate_taproot_spend_info().output_key(),
                    self.network,
                )
            },
        }
    }
}

