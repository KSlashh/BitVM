use crate::{
    treepp::*,
    bridge::groth16,
};
use bitcoin::{
    key::Secp256k1, Witness,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, XOnlyPublicKey,
};

use super::{
    super::transactions::base::Input,
    connector::*,
};

#[derive(Clone)]
pub struct Revealer<'a> {
    pub network: Network,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
    pub bitcommitment_script: &'a Script,
}

impl<'a> Revealer<'a> {
    pub fn new(
        network: Network,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        bitcommitment_script: &'a Script,
    ) -> Self {
        Revealer {
            network,
            n_of_n_taproot_public_key: n_of_n_taproot_public_key.clone(),
            bitcommitment_script,
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        self.bitcommitment_script.clone().compile()
    }

    pub fn push_leaf_0_unlock_witness(&self, witness: &mut Witness, unlock_script: Script) {
        let wit = groth16::script_to_witness(unlock_script);
        for w in wit {
            witness.push(w);
        }
    }
}

impl<'a> TaprootConnector for Revealer<'a> {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => generate_default_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(0, self.generate_taproot_leaf_0_script())
            .expect("Unable to add leaf 0")
            .finalize(&Secp256k1::new(), self.n_of_n_taproot_public_key) 
            .expect("Unable to finalize ttaproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}
