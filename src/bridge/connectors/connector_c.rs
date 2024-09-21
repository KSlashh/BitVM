use crate::{bridge::graphs::base::CALC_ROUND, treepp::script};
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

// Specialized for assert leaves currently.
pub type LockScript = fn(index: u32) -> ScriptBuf;
pub type UnlockWitnessData = Vec<u8>;
pub type UnlockWitness = fn(index: u32) -> UnlockWitnessData;

pub struct DisproveLeaf {
    pub lock: LockScript,
    pub unlock: UnlockWitness,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ConnectorC {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
    pub operator_commitment_pubkey: WPublicKey,
}

impl ConnectorC {
    pub fn new(network: Network, operator_taproot_public_key: &XOnlyPublicKey, operator_commitment_pubkey: &WPublicKey,) -> Self {
        ConnectorC {
            network,
            operator_taproot_public_key: operator_taproot_public_key.clone(),
            operator_commitment_pubkey: operator_commitment_pubkey.clone(),
        }
    }

    pub fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        script! {
            { hash_chain::chunk_script_lock(&self.operator_commitment_pubkey, leaf_index) }
        }
        .compile()
    }

    pub fn push_leaf_unlock_witness(&self, witness: &mut Witness, pre_commitment: &Witness, post_commitment: &Witness, leaf_index: u32) {
        witness.push([0x1]);
        hash_chain::push_chunk_unlock_witness(witness, pre_commitment, post_commitment);
    }
}

impl TaprootConnector for ConnectorC {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        self.generate_taproot_leaf_script(leaf_index)
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        let index = leaf_index.to_usize().unwrap();
        if index >= CALC_ROUND as usize {
            panic!("Invalid leaf index.")
        }
        generate_default_tx_in(input)
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        let mut lock_scripts = Vec::with_capacity(CALC_ROUND as usize);
        for i in 0..CALC_ROUND {
            lock_scripts.push(self.generate_taproot_leaf_script(i))
        }
        let script_weights = lock_scripts.iter().map(|script| (1, script.clone()));

        TaprootBuilder::with_huffman_tree(script_weights)
            .expect("Unable to add assert leaves")
            .finalize(&Secp256k1::new(), self.operator_taproot_public_key)
            .expect("Unable to finalize assert transaction connector c taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}

