use bitcoin::{Address, Amount, Transaction, Txid};
use bitcoincore_rpc::Client;
use bitvm::bridge::{
    connectors::connector_c::ConnectorC, contexts::{depositor::DepositorContext, operator::OperatorContext, verifier::VerifierContext}, transactions::{
        assert::AssertTransaction,
        base::{BaseTransaction, Input},
        kick_off_1::KickOff1Transaction,
        kick_off_2::KickOff2Transaction,
        peg_in_confirm::PegInConfirmTransaction,
    }
};

use crate::bridge::helper::{generate_stub_outpoint, self};

pub async fn create_and_mine_kick_off_1_tx<'a>(
    rpc: &Client,
    operator_context: &OperatorContext,
    kick_off_1_funding_utxo_address: &Address,
    input_amount: Amount,
) -> (Transaction, Txid) {
    let kick_off_1_funding_outpoint =
        generate_stub_outpoint(&rpc, kick_off_1_funding_utxo_address, input_amount);
    let kick_off_1_input = Input {
        outpoint: kick_off_1_funding_outpoint,
        amount: input_amount,
    };
    let kick_off_1 = KickOff1Transaction::new(&operator_context, kick_off_1_input);
    let kick_off_1_tx = kick_off_1.finalize();
    let kick_off_1_txid = kick_off_1_tx.compute_txid();

    // mine kick-off 1 tx
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &kick_off_1_tx);
    helper::mint_block(&rpc, 1);
    helper::validate_tx(&rpc, kick_off_1_txid);

    return (kick_off_1_tx, kick_off_1_txid);
}

pub async fn create_and_mine_kick_off_2_tx<'a>(
    rpc: &Client,
    operator_context: &OperatorContext,
    kick_off_2_funding_utxo_address: &Address,
    input_amount: Amount,
) -> (Transaction, Txid) {
    let kick_off_2_funding_outpoint =
        generate_stub_outpoint(&rpc, kick_off_2_funding_utxo_address, input_amount);
    let kick_off_2_input = Input {
        outpoint: kick_off_2_funding_outpoint,
        amount: input_amount,
    };
    let kick_off_2 = KickOff2Transaction::new(&operator_context, kick_off_2_input);
    let kick_off_2_tx = kick_off_2.finalize();
    let kick_off_2_txid = kick_off_2_tx.compute_txid();

    // mine kick-off 2 tx
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &kick_off_2_tx);
    helper::mint_block(&rpc, 1);
    helper::validate_tx(&rpc, kick_off_2_txid);

    return (kick_off_2_tx, kick_off_2_txid);
}

pub async fn create_and_mine_assert_tx<'a>(
    rpc: &Client,
    operator_context: &OperatorContext,
    assert_funding_utxo_address: &Address,
    input_amount: Amount,
    connector_c: ConnectorC<'a>,
) -> (Transaction, Txid) {
    // create assert tx
    let assert_funding_outpoint =
        generate_stub_outpoint(&rpc, assert_funding_utxo_address, input_amount);
    let assert_input = Input {
        outpoint: assert_funding_outpoint,
        amount: input_amount,
    };
    let assert = AssertTransaction::new(&operator_context, assert_input, connector_c);

    let assert_tx = assert.finalize();
    let assert_txid = assert_tx.compute_txid();

    // mine assert tx
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &assert_tx);
    helper::mint_block(&rpc, 1);
    helper::validate_tx(&rpc, assert_txid);

    return (assert_tx, assert_txid);
}

pub async fn create_and_mine_peg_in_confirm_tx<'a>(
    rpc: &Client,
    depositor_context: &DepositorContext,
    verifier_0_context: &VerifierContext,
    verifier_1_context: &VerifierContext,
    evm_address: &str,
    funding_address: &Address,
    input_amount: Amount,
) -> (Transaction, Txid) {
    let peg_in_confirm_funding_outpoint =
        generate_stub_outpoint(rpc, &funding_address, input_amount);

    let confirm_input = Input {
        outpoint: peg_in_confirm_funding_outpoint,
        amount: input_amount,
    };
    let mut peg_in_confirm =
        PegInConfirmTransaction::new(depositor_context, evm_address, confirm_input);

    let secret_nonces_0 = peg_in_confirm.push_nonces(&verifier_0_context);
    let secret_nonces_1 = peg_in_confirm.push_nonces(&verifier_1_context);

    peg_in_confirm.pre_sign(&verifier_0_context, &secret_nonces_0);
    peg_in_confirm.pre_sign(&verifier_1_context, &secret_nonces_1);

    let peg_in_confirm_tx = peg_in_confirm.finalize();
    let peg_in_confirm_txid = peg_in_confirm_tx.compute_txid();

    // mine peg-in confirm
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &peg_in_confirm_tx);
    helper::mint_block(&rpc, 1);
    helper::validate_tx(&rpc, peg_in_confirm_txid);

    return (peg_in_confirm_tx, peg_in_confirm_txid);
}
