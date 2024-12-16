use bitcoin::{
    absolute, Amount, Network, PublicKey, ScriptBuf, Transaction, TxOut,
    XOnlyPublicKey,
};
use musig2::{secp256k1::schnorr::Signature, PartialSignature, PubNonce};
use std::collections::HashMap;
use crate::bridge::graphs::base::HUGE_FEE_AMOUNT;
use crate::treepp::*;

use super::{
    super::{
        connectors::{
            connector::*, connector_4::Connector4, connector_5::Connector5,
            connector_b::ConnectorB, connector_c::ConnectorC, revealer::Revealer,
        },
        contexts::operator::OperatorContext,
        graphs::base::DUST_AMOUNT,
        groth16,
    },
    base::*,
    pre_signed::*,
    pre_signed_musig2::*,
};
use super::signing::push_taproot_leaf_script_and_control_block_to_witness;

#[allow(dead_code)]
#[derive(Clone)]
pub struct AssertTransaction<'a> {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
    connector_b: ConnectorB,
    connector_c: ConnectorC<'a>,
    revealers: Vec<Revealer<'a>>,
    musig2_nonces: HashMap<usize, HashMap<PublicKey, PubNonce>>,
    musig2_nonce_signatures: HashMap<usize, HashMap<PublicKey, Signature>>,
    musig2_signatures: HashMap<usize, HashMap<PublicKey, PartialSignature>>,
}

impl<'a> PreSignedTransaction for AssertTransaction<'a> {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl<'a> PreSignedMusig2Transaction for AssertTransaction<'a> {
    fn musig2_nonces(&self) -> &HashMap<usize, HashMap<PublicKey, PubNonce>> { &self.musig2_nonces }
    fn musig2_nonces_mut(&mut self) -> &mut HashMap<usize, HashMap<PublicKey, PubNonce>> {
        &mut self.musig2_nonces
    }
    fn musig2_nonce_signatures(&self) -> &HashMap<usize, HashMap<PublicKey, Signature>> {
        &self.musig2_nonce_signatures
    }
    fn musig2_nonce_signatures_mut(
        &mut self,
    ) -> &mut HashMap<usize, HashMap<PublicKey, Signature>> {
        &mut self.musig2_nonce_signatures
    }
    fn musig2_signatures(&self) -> &HashMap<usize, HashMap<PublicKey, PartialSignature>> {
        &self.musig2_signatures
    }
    fn musig2_signatures_mut(
        &mut self,
    ) -> &mut HashMap<usize, HashMap<PublicKey, PartialSignature>> {
        &mut self.musig2_signatures
    }
}

impl<'a> AssertTransaction<'a> {
    pub fn new(
        context: &OperatorContext, 
        input_0: Input, 
        bitcommitment_inputs: Vec<Input>, 
        connector_c: ConnectorC<'a>, 
        revealers: Vec<Revealer<'a>>,
    ) -> Self {
        let mut this = Self::new_for_validation(
            context.network,
            &context.operator_public_key,
            &context.operator_taproot_public_key,
            &context.n_of_n_taproot_public_key,
            connector_c,
            revealers,
            input_0,
            bitcommitment_inputs,
        );

        // sign input[0], leaf[1]
        this.connector_b.push_leaf_1_unlock_witness(&mut this.tx.input[0].witness);
        let redeem_script = this.connector_b.generate_taproot_leaf_script(1);
        let taproot_spend_info = this.connector_b.generate_taproot_spend_info();
        push_taproot_leaf_script_and_control_block_to_witness(&mut this.tx, 0, &taproot_spend_info, &redeem_script);

        this
    }

    pub fn new_for_validation(
        network: Network,
        operator_public_key: &PublicKey,
        _operator_taproot_public_key: &XOnlyPublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        connector_c: ConnectorC<'a>,
        revealers: Vec<Revealer<'a>>,
        input_0: Input,
        bitcommitment_inputs: Vec<Input>,
    ) -> Self {
        let connector_4 = Connector4::new(network, operator_public_key);
        let connector_5 = Connector5::new(network, n_of_n_taproot_public_key);
        let connector_b = ConnectorB::new(network, n_of_n_taproot_public_key);

        let input_0_leaf = 1;
        let _input_0 = connector_b.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let mut inputs_vec = vec![_input_0];
        let mut total_output_amount = input_0.amount;

        assert!(revealers.len() == bitcommitment_inputs.len(), "bitcommitment_inputs number not match");
        let bitcommitment_inputs_leaf = 0;
        for i in 0..revealers.len() {
            let input_i = revealers[i].generate_taproot_leaf_tx_in(bitcommitment_inputs_leaf, &bitcommitment_inputs[i]);
            inputs_vec.push(input_i);
            total_output_amount += bitcommitment_inputs[i].amount;
        }

        total_output_amount -= Amount::from_sat(HUGE_FEE_AMOUNT);

        let _output_0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_4.generate_address().script_pubkey(),
        };

        let _output_1 = TxOut {
            value: total_output_amount - Amount::from_sat(DUST_AMOUNT) * 2,
            script_pubkey: connector_5.generate_taproot_address().script_pubkey(),
        };

        let _output_2 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_c.generate_taproot_address().script_pubkey(),
        };

        AssertTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: inputs_vec,
                output: vec![_output_0, _output_1, _output_2],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_b.generate_taproot_leaf_script(input_0_leaf)],
            connector_b,
            connector_c,
            revealers,
            musig2_nonces: HashMap::new(),
            musig2_nonce_signatures: HashMap::new(),
            musig2_signatures: HashMap::new(),
        }
    }

    pub fn num_blocks_timelock_0(&self) -> u32 { self.connector_b.num_blocks_timelock_1 }

    pub fn push_bitcommitments_witness(
        &mut self,
        bitcommitments_unlock_script: Vec<Script>,
    ) {
        assert!(bitcommitments_unlock_script.len() == self.tx.input.len()-1, "bitcommitments number not match");
        let bitcommitment_leaf_index = 0;
        for i in 0..bitcommitments_unlock_script.len() {
            let input_index = i+1;
            let witness = &mut self.tx.input[input_index].witness;
            let wit = groth16::script_to_witness(bitcommitments_unlock_script[i].clone());
            for w in wit {
                witness.push(w);
            }
            let scr = self.revealers[i].generate_taproot_leaf_script(bitcommitment_leaf_index);
            let taproot_spend_info = self.revealers[i].generate_taproot_spend_info();
            push_taproot_leaf_script_and_control_block_to_witness(
                &mut self.tx,
                input_index,
                &taproot_spend_info,
                &scr,
            );
        }
    }
}

impl<'a> BaseTransaction for AssertTransaction<'a> {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
