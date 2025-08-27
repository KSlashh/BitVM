use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use crate::{
    commitments::CommitmentMessageId,
    common::ZkProofVerifyingKey,
    connectors::base::*,
    error::{ChunkerError, Error},
    transactions::base::Input,
    utils::{cleanup_cache_files, remove_script_and_control_block_from_witness},
};
use bitcoin::{
    address::{NetworkChecked, NetworkUnchecked},
    hashes::{hash160, Hash},
    hex::DisplayHex,
    key::TweakedPublicKey,
    taproot::{ControlBlock, LeafVersion, TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TapNodeHash, Transaction, TxIn, XOnlyPublicKey,
};
use num_traits::ToPrimitive;
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};

use bitvm::{
    chunk::api::{
        api_generate_full_tapscripts, api_generate_partial_script,
        type_conversion_utils::{
            script_to_witness, utils_signatures_from_raw_witnesses, utils_typed_pubkey_from_raw,
            RawProof, RawWitness,
        },
        validate_assertions, PublicKeys,
    },
    // chunker::{
    //     assigner::BridgeAssigner,
    //     chunk_groth16_verifier::groth16_verify_to_segments,
    //     common::RawWitness,
    //     disprove_execution::{disprove_exec, RawProof},
    // },
    signatures::{signing_winternitz::WinternitzPublicKey, winternitz},
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ConnectorE {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
    pub address: Address<NetworkUnchecked>,
    pub taproot_merkle_root: Option<TapNodeHash>,
}

impl ConnectorE {
    pub fn new_with_scripts(
        network: Network,
        operator_taproot_public_key: &XOnlyPublicKey,
        lock_scripts: Vec<ScriptBuf>,
    ) -> (Self, TaprootSpendInfo) {
        // println!("Generating new taproot spend info for connector E...");
        let script_weights = lock_scripts.into_iter().map(|b| (1, b));
        let spend_info = TaprootBuilder::with_huffman_tree(script_weights)
            .expect("Unable to add assert leaves")
            .finalize(SECP256K1, *operator_taproot_public_key)
            .expect("Unable to finalize assert transaction connector c taproot");
        let address = Address::p2tr_tweaked(spend_info.output_key(), network);
        let merkle_root = spend_info.merkle_root();
        (
            ConnectorE {
                network,
                operator_taproot_public_key: *operator_taproot_public_key,
                address: address.as_unchecked().clone(),
                taproot_merkle_root: merkle_root,
            },
            spend_info,
        )
    }

    pub fn new_with_precomputed_info(
        network: Network,
        operator_taproot_public_key: &XOnlyPublicKey,
        address: &Address<NetworkUnchecked>,
        taproot_merkle_root: Option<TapNodeHash>,
    ) -> Self {
        ConnectorE {
            network,
            operator_taproot_public_key: *operator_taproot_public_key,
            address: address.clone(),
            taproot_merkle_root,
        }
    }

    pub fn generate_taproot_address(&self) -> Address {
        self.address.clone().assume_checked()
    }

    pub fn taproot_merkle_root(&self) -> Option<TapNodeHash> {
        self.taproot_merkle_root
    }
}
