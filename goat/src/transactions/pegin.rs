use bitcoin::{
    absolute,
    consensus::{self},
    Address, Amount, ScriptBuf, Transaction, TxIn, TxOut,
};
use serde::{Deserialize, Serialize};

use crate::{
    connectors::connector_0::Connector0,
    transactions::signing::populate_taproot_input_witness_with_signature,
};

use super::{
    super::connectors::{base::*, connector_z::ConnectorZ},
    base::*,
    pre_signed::*,
    signing::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PegInDepositTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    fee_amount: Amount,
    pub input_amounts: Vec<Amount>,
}

impl PegInDepositTransaction {
    pub fn new_unsigned(
        connector_z: &ConnectorZ,
        inputs: Vec<Input>,
        deposit_amount: Amount,
        fee_amount: Amount,
        change_address: Address,
    ) -> Self {
        let mut total_input_amount = Amount::ZERO;
        let input_amounts: Vec<Amount> = inputs.iter().map(|input| input.amount).collect();
        let txins: Vec<TxIn> = inputs
            .iter()
            .map(|input| {
                total_input_amount += input.amount;
                generate_default_tx_in(input)
            })
            .collect();
        let change_amount = total_input_amount - deposit_amount - fee_amount;
        let mut txouts = vec![];
        let output_0 = TxOut {
            value: deposit_amount,
            script_pubkey: connector_z.generate_taproot_address().script_pubkey(),
        };
        txouts.push(output_0);
        let mut fee_amount = fee_amount;
        if change_amount > Amount::from_sat(DUST_AMOUNT) {
            let output_1 = TxOut {
                value: change_amount,
                script_pubkey: change_address.script_pubkey(),
            };
            txouts.push(output_1);
        } else {
            fee_amount += change_amount;
        }

        PegInDepositTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: txins,
                output: txouts,
            },
            fee_amount,
            input_amounts,
        }
    }

    pub fn tx_mut(&mut self) -> &mut Transaction {
        &mut self.tx
    }

    pub fn tx(&self) -> &Transaction {
        &self.tx
    }
}

impl BaseTransaction for PegInDepositTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "PegInDeposit"
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PegInRefundTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for PegInRefundTransaction {
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

impl PegInRefundTransaction {
    pub fn new_with_signature(
        connector_z: &ConnectorZ,
        input_0: Input,
        refund_address: &Address,
        fee_amount: Amount,
        signature: bitcoin::taproot::Signature,
    ) -> Self {
        let mut this = Self::new_for_validation(connector_z, input_0, refund_address, fee_amount);

        this.sign_input_0_with_signature(connector_z, signature);

        this
    }

    pub fn new_for_validation(
        connector_z: &ConnectorZ,
        input_0: Input,
        refund_address: &Address,
        fee_amount: Amount,
    ) -> Self {
        let input_0_leaf = 1;
        let _input_0 = connector_z.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let total_output_amount = input_0.amount - fee_amount;

        let _output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: refund_address.script_pubkey(),
        };

        PegInRefundTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![_output_0],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_z.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_z.generate_taproot_leaf_script(input_0_leaf)],
        }
    }

    fn sign_input_0_with_signature(
        &mut self,
        connector_z: &ConnectorZ,
        signature: bitcoin::taproot::Signature,
    ) {
        let input_index = 0;
        let script = &self.prev_scripts()[input_index].clone();
        let taproot_spend_info = connector_z.generate_taproot_spend_info();

        populate_taproot_input_witness_with_signature(
            self.tx_mut(),
            input_index,
            &taproot_spend_info,
            script,
            &[signature],
        );
    }
}

impl BaseTransaction for PegInRefundTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "PegInRefund"
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PegInConfirmTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for PegInConfirmTransaction {
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

impl PegInConfirmTransaction {
    pub fn new_for_validation(
        connector_0: &Connector0,
        connector_z: &ConnectorZ,
        input_0: Input,
        fee_amount: Amount,
    ) -> Self {
        let input_0_leaf = 0;
        let _input_0 = connector_z.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let total_output_amount = input_0.amount - fee_amount;

        let _output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: connector_0.generate_taproot_address().script_pubkey(),
        };

        PegInConfirmTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![_output_0],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_z.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_z.generate_taproot_leaf_script(input_0_leaf)],
        }
    }

    pub fn push_pre_sigs(
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
}

impl BaseTransaction for PegInConfirmTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "PegInConfirm"
    }
}
