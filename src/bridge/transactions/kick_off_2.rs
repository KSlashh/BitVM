use bitcoin::{
    absolute, Amount, Network, PublicKey, ScriptBuf, Transaction, TxOut,
    XOnlyPublicKey,
};

use crate::bridge::graphs::base::LARGE_FEE_AMOUNT;

use super::{
    super::{
        connectors::{
            connector::*, connector_1::Connector1, connector_3::Connector3, connector_b::ConnectorB, revealer::Revealer,
        },
        contexts::operator::OperatorContext,
        graphs::base::DUST_AMOUNT,
    },
    base::*,
    pre_signed::*,
};
use super::signing::push_taproot_leaf_script_and_control_block_to_witness;

#[derive(Clone)]
pub struct KickOff2Transaction {
    tx: Transaction,
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

impl<'a> KickOff2Transaction {
    pub fn new(context: &OperatorContext, input_0: Input , revealers: Vec<Revealer<'a>>) -> Self {
        let mut this = Self::new_for_validation(
            context.network,
            &context.operator_public_key,
            &context.operator_taproot_public_key,
            &context.n_of_n_taproot_public_key,
            input_0,
            revealers,
        );

        // sign input[0], leaf_0
        this.connector_1.push_leaf_0_unlock_witness(&mut this.tx.input[0].witness);
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
        input_0: Input,
        revealers: Vec<Revealer<'a>>,
    ) -> Self {
        let connector_1 = Connector1::new(
            network,
            operator_taproot_public_key,
            n_of_n_taproot_public_key,
        );
        let connector_3 = Connector3::new(network, operator_public_key);
        let connector_b = ConnectorB::new(network, n_of_n_taproot_public_key);

        let input_0_leaf = 0;
        let _input_0 = connector_1.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let total_output_amount = input_0.amount - Amount::from_sat(LARGE_FEE_AMOUNT);

        let _output_0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_3.generate_address().script_pubkey(),
        };

        let connector_b_amount = total_output_amount - Amount::from_sat(DUST_AMOUNT*(1+revealers.len() as u64));
        let _output_1 = TxOut {
            value: connector_b_amount,
            script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
        };

        let mut output_vec = vec![_output_0, _output_1];

        for i in 0..revealers.len() {
            let output_i = TxOut {
                value: Amount::from_sat(DUST_AMOUNT),
                script_pubkey: revealers[i].generate_taproot_address().script_pubkey(),
            };
            output_vec.push(output_i);
        }

        KickOff2Transaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: output_vec,
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

impl<'a> BaseTransaction for KickOff2Transaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
