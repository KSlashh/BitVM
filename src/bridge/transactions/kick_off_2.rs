use bitcoin::{
    absolute, consensus, Amount, Network, PublicKey, ScriptBuf, TapSighashType, Transaction, TxOut,
    XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{
            connector::*, connector_1::Connector1, connector_3::Connector3, connector_b::ConnectorB,
        },
        contexts::operator::OperatorContext,
        graphs::base::{DUST_AMOUNT, HUGE_FEE_AMOUNT},
    },
    base::*,
    pre_signed::*,
};
use crate::bridge::commitment::WPublicKey;
use super::signing::push_taproot_leaf_script_and_control_block_to_witness;

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct KickOff2Transaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
    connector_1: Connector1,
}

impl PreSignedTransaction for KickOff2Transaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl KickOff2Transaction {
    pub fn new(context: &OperatorContext, input_0: Input, statement: &[u8]) -> Self {
        let mut this = Self::new_for_validation(
            context.network,
            &context.operator_public_key,
            &context.operator_taproot_public_key,
            &context.n_of_n_taproot_public_key,
            &context.operator_commitment_pubkey,
            input_0,
        );

        // sign input[0], leaf_0
        this.connector_1.push_leaf_0_unlock_witness(&mut this.tx.input[0].witness, &context.operator_commitment_seckey, statement);
        let redeem_script = this.connector_1.generate_taproot_leaf_script(0);
        let taproot_spend_info = this.connector_1.generate_taproot_spend_info();
        push_taproot_leaf_script_and_control_block_to_witness(&mut this.tx, 0, &taproot_spend_info, &redeem_script);

        this
    }

    pub fn new_for_validation(
        network: Network,
        operator_public_key: &PublicKey,
        operator_taproot_public_key: &XOnlyPublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        operator_commitment_pubkey: &WPublicKey,
        input_0: Input,
    ) -> Self {
        let connector_1 = Connector1::new(
            network,
            operator_taproot_public_key,
            n_of_n_taproot_public_key,
            operator_commitment_pubkey,
        );
        let connector_3 = Connector3::new(network, operator_public_key);
        let connector_b = ConnectorB::new(network, n_of_n_taproot_public_key, operator_commitment_pubkey);

        let input_0_leaf = 0;
        let _input_0 = connector_1.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let total_output_amount = input_0.amount - Amount::from_sat(HUGE_FEE_AMOUNT);

        let _output_0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_3.generate_address().script_pubkey(),
        };

        let _output_1 = TxOut {
            value: total_output_amount - Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
        };

        KickOff2Transaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![_output_0, _output_1],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_1.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_1.generate_taproot_leaf_script(input_0_leaf)],
            connector_1,
        }
    }

    pub fn num_blocks_timelock_0(&self) -> u32 { self.connector_1.num_blocks_timelock_0 }
}

impl BaseTransaction for KickOff2Transaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
