use bitcoin::{
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, XOnlyPublicKey,
};
use bitvm::signatures::{signing_winternitz::WinternitzPublicKey, CompactWots, Wots, Wots32};
use bitvm::treepp::script;
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};

use super::{
    super::{scripts::*, transactions::base::Input},
    base::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ConnectorG {
    pub network: Network,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
    pub operator_taproot_public_key: XOnlyPublicKey,
    pub blockhash_wots_pubkey: WinternitzPublicKey,
    pub operator_commit_blocks_timelock: u32,
}

impl ConnectorG {
    pub fn new(
        network: Network,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        operator_taproot_public_key: &XOnlyPublicKey,
        blockhash_wots_pubkey: &<Wots32 as Wots>::PublicKey,
        operator_commit_blocks_timelock: u32,
    ) -> Self {
        let blockhash_wots_pubkey = WinternitzPublicKey {
            public_key: blockhash_wots_pubkey.to_vec(),
            parameters: <Wots32 as Wots>::PARAMETERS,
        };
        ConnectorG {
            network,
            n_of_n_taproot_public_key: *n_of_n_taproot_public_key,
            operator_taproot_public_key: *operator_taproot_public_key,
            blockhash_wots_pubkey,
            operator_commit_blocks_timelock,
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        let blockhash_wots_pubkey: <Wots32 as Wots>::PublicKey = self
            .blockhash_wots_pubkey
            .public_key
            .as_slice()
            .try_into()
            .unwrap();
        script! {
            { Wots32::compact_checksig_verify_and_clear_stack(&blockhash_wots_pubkey) }
        }
        .compile()
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }

    fn generate_taproot_leaf_1_script(&self) -> ScriptBuf {
        generate_timelock_taproot_script(
            &self.n_of_n_taproot_public_key,
            self.operator_commit_blocks_timelock,
        )
    }

    fn generate_taproot_leaf_1_tx_in(&self, input: &Input) -> TxIn {
        generate_timelock_tx_in(input, self.operator_commit_blocks_timelock)
    }
}

impl TaprootConnector for ConnectorG {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_script(),
            1 => self.generate_taproot_leaf_1_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_tx_in(input),
            1 => self.generate_taproot_leaf_1_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(1, self.generate_taproot_leaf_0_script())
            .expect("Unable to add leaf 0")
            .add_leaf(1, self.generate_taproot_leaf_1_script())
            .expect("Unable to add leaf 1")
            .finalize(SECP256K1, self.n_of_n_taproot_public_key)
            .expect("Unable to finalize taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}
