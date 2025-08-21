use bitcoin::{
    absolute, consensus, Address, Amount, ScriptBuf, TapSighashType, Transaction, TxOut,
};
use musig2::{errors::SigningError, AggNonce, PartialSignature, SecNonce};
use serde::{Deserialize, Serialize};

use crate::transactions::signing_musig2::generate_taproot_partial_signature;

use super::{
    super::{
        connectors::{
            base::*, connector_0::Connector0, connector_a::ConnectorA,
            kickoff_connectors::GuardianConnector,
        },
        contexts::{operator::OperatorContext, verifier::VerifierContext},
        scripts::*,
    },
    base::*,
    pre_signed::*,
    signing::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Take1Transaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for Take1Transaction {
    fn tx(&self) -> &Transaction {
        &self.tx
    }

    fn tx_mut(&mut self) -> &mut Transaction {
        &mut self.tx
    }

    fn prev_outs(&self) -> &Vec<TxOut> {
        &self.prev_outs
    }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> {
        &self.prev_scripts
    }
}

impl Take1Transaction {
    pub fn new_for_validation(
        connector_0: &Connector0,
        connector_a: &ConnectorA,
        guardian_connector: &GuardianConnector,
        input_0: Input,
        input_1: Input,
        input_2: Input,
        operator_address: &Address,
    ) -> Self {
        let input_0_leaf = 0;
        let _input_0 = connector_0.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let input_1_leaf = 0;
        let _input_1 = connector_a.generate_taproot_leaf_tx_in(input_1_leaf, &input_1);

        let input_2_leaf = 0;
        let _input_2 = guardian_connector.generate_taproot_leaf_tx_in(input_2_leaf, &input_2);

        let total_output_amount = input_0.amount + input_1.amount + input_2.amount
            - Amount::from_sat(MIN_RELAY_FEE_TAKE_1);

        let output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: operator_address.script_pubkey(),
        };

        let output_1 = p2a_output();

        Take1Transaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0, _input_1, _input_2],
                output: vec![output_0, output_1],
            },
            prev_outs: vec![
                TxOut {
                    value: input_0.amount,
                    script_pubkey: connector_0.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: input_1.amount,
                    script_pubkey: connector_a.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: input_2.amount,
                    script_pubkey: guardian_connector
                        .generate_taproot_address()
                        .script_pubkey(),
                },
            ],
            prev_scripts: vec![
                connector_0.generate_taproot_leaf_script(input_0_leaf),
                connector_a.generate_taproot_leaf_script(input_1_leaf),
                guardian_connector.generate_taproot_leaf_script(input_2_leaf),
            ],
        }
    }

    fn sign_input_0_musig2(
        &mut self,
        context: &VerifierContext,
        sec_nonce: &SecNonce,
        agg_nonce: &AggNonce,
    ) -> Result<PartialSignature, SigningError> {
        let input_index = 0;
        let sighash_type = TapSighashType::All;
        generate_taproot_partial_signature(
            &context,
            self.tx(),
            sec_nonce,
            agg_nonce,
            input_index,
            self.prev_outs(),
            &self.prev_scripts()[input_index],
            sighash_type,
        )
    }

    fn push_input_0_signature(
        &mut self,
        connector_0: &Connector0,
        input_0_sig: bitcoin::taproot::Signature,
    ) {
        let input_index = 0;
        let script = self.prev_scripts()[input_index].clone();
        let spend_info = connector_0.generate_taproot_spend_info();
        let tx_mut = self.tx_mut();
        // Push signature to witness
        tx_mut.input[input_index]
            .witness
            .push(input_0_sig.serialize());

        // Push script + control block
        push_taproot_leaf_script_and_control_block_to_witness(
            tx_mut,
            input_index,
            &spend_info,
            &script,
        );
    }

    pub fn pre_sign(
        &mut self,
        context: &VerifierContext,
        sec_nonces: &[SecNonce; 1],
        agg_nonces: &[AggNonce; 1],
    ) -> Result<[PartialSignature; 1], SigningError> {
        let input_0_sig = self.sign_input_0_musig2(context, &sec_nonces[0], &agg_nonces[0]);
        match [input_0_sig]
            .into_iter()
            .collect::<Result<Vec<PartialSignature>, SigningError>>()
        {
            Ok(sigs) => Ok(sigs.try_into().unwrap()),
            Err(e) => Err(e),
        }
    }

    pub fn push_pre_sigs(
        &mut self,
        connector_0: &Connector0,
        pre_sigs: [bitcoin::taproot::Signature; 1],
    ) {
        self.push_input_0_signature(connector_0, pre_sigs[0].clone());
    }

    pub fn sign_input_1(&mut self, context: &OperatorContext, connector_a: &ConnectorA) {
        let input_index = 1;
        pre_sign_taproot_input_default(
            self,
            input_index,
            TapSighashType::All,
            connector_a.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }

    pub fn sign_input_2(
        &mut self,
        context: &OperatorContext,
        guardian_connector: &GuardianConnector,
    ) {
        let input_index = 2;
        pre_sign_taproot_input_default(
            self,
            input_index,
            TapSighashType::All,
            guardian_connector.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }
}

impl BaseTransaction for Take1Transaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "Take1"
    }
}
