use std::time::Duration;

use bitcoin::{Amount, OutPoint};

use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        peg_in_confirm::PegInConfirmTransaction,
        peg_in_deposit::PegInDepositTransaction,
        peg_in_refund::PegInRefundTransaction,
    },
};
use tokio::time::sleep;

use crate::bridge::{helper::{generate_stub_outpoint, self}, setup::setup_test};

#[tokio::test]
async fn test_peg_in_success() {
    let empty_script = vec![];
    let (
        rpc,
        depositor_context,
        _,
        verifier_0_context,
        verifier_1_context,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        depositor_evm_address,
        _,
    ) = setup_test(&empty_script, &empty_script).await;

    let input_amount_raw = INITIAL_AMOUNT + FEE_AMOUNT * 2;
    let deposit_input_amount = Amount::from_sat(input_amount_raw);

    // peg-in deposit
    let deposit_funding_utxo_address = generate_pay_to_pubkey_script_address(
        depositor_context.network,
        &depositor_context.depositor_public_key,
    );
    let deposit_funding_outpoint =
        generate_stub_outpoint(&rpc, &deposit_funding_utxo_address, deposit_input_amount);
    let deposit_input = Input {
        outpoint: deposit_funding_outpoint,
        amount: deposit_input_amount,
    };

    let peg_in_deposit =
        PegInDepositTransaction::new(&depositor_context, &depositor_evm_address, deposit_input);

    let peg_in_deposit_tx = peg_in_deposit.finalize();
    let deposit_txid = peg_in_deposit_tx.compute_txid();
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &peg_in_deposit_tx);
    helper::mint_block(&rpc, 1);
    helper::validate_tx(&rpc, deposit_txid);
    println!("Peg-in Txid: {:?}", deposit_txid);

    // peg-in confirm
    let output_index = 0;
    let confirm_funding_outpoint = OutPoint {
        txid: deposit_txid,
        vout: output_index,
    };
    let confirm_input = Input {
        outpoint: confirm_funding_outpoint,
        amount: peg_in_deposit_tx.output[output_index as usize].value,
    };
    let mut peg_in_confirm =
        PegInConfirmTransaction::new(&depositor_context, &depositor_evm_address, confirm_input);

    let secret_nonces_0 = peg_in_confirm.push_nonces(&verifier_0_context);
    let secret_nonces_1 = peg_in_confirm.push_nonces(&verifier_1_context);

    peg_in_confirm.pre_sign(&verifier_0_context, &secret_nonces_0);
    peg_in_confirm.pre_sign(&verifier_1_context, &secret_nonces_1);

    let peg_in_confirm_tx = peg_in_confirm.finalize();
    let confirm_txid = peg_in_confirm_tx.compute_txid();
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &peg_in_confirm_tx);
    helper::mint_block(&rpc, 1);
    helper::validate_tx(&rpc, confirm_txid);
    println!("Confirm Txid: {:?}", confirm_txid);

    // multi-sig balance check 
    // TODO
}

#[tokio::test]
async fn test_peg_in_time_lock_not_surpassed() {
    let empty_script = vec![];
    let (
        rpc,
        depositor_context,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        depositor_evm_address,
        _,
    ) = setup_test(&empty_script, &empty_script).await;

    let input_amount_raw = INITIAL_AMOUNT + FEE_AMOUNT * 2;
    let deposit_input_amount = Amount::from_sat(input_amount_raw);

    // peg-in deposit
    let deposit_funding_utxo_address = generate_pay_to_pubkey_script_address(
        depositor_context.network,
        &depositor_context.depositor_public_key,
    );
    let deposit_funding_outpoint =
        generate_stub_outpoint(&rpc, &deposit_funding_utxo_address, deposit_input_amount);
    let deposit_input = Input {
        outpoint: deposit_funding_outpoint,
        amount: deposit_input_amount,
    };

    let peg_in_deposit =
        PegInDepositTransaction::new(&depositor_context, &depositor_evm_address, deposit_input);
    let peg_in_deposit_tx = peg_in_deposit.finalize();
    let deposit_txid = peg_in_deposit_tx.compute_txid();
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &peg_in_deposit_tx);
    helper::mint_block(&rpc, 1);
    helper::validate_tx(&rpc, deposit_txid);

    // peg-in refund
    let output_index = 0;
    let refund_funding_outpoint = OutPoint {
        txid: deposit_txid,
        vout: output_index,
    };
    let refund_input = Input {
        outpoint: refund_funding_outpoint,
        amount: peg_in_deposit_tx.output[output_index as usize].value,
    };
    let peg_in_refund =
        PegInRefundTransaction::new(&depositor_context, &depositor_evm_address, refund_input);
    let _peg_in_refund_tx = peg_in_refund.finalize();

    // mine peg-in refund failed
    // TODO
}

#[tokio::test]
async fn test_peg_in_time_lock_surpassed() {
    let empty_script = vec![];
    let (
        rpc,
        depositor_context,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        depositor_evm_address,
        _,
    ) = setup_test(&empty_script, &empty_script).await;

    let input_amount_raw = INITIAL_AMOUNT + FEE_AMOUNT * 2;
    let deposit_input_amount = Amount::from_sat(input_amount_raw);

    // peg-in deposit
    let deposit_funding_utxo_address = generate_pay_to_pubkey_script_address(
        depositor_context.network,
        &depositor_context.depositor_public_key,
    );
    let deposit_funding_outpoint =
        generate_stub_outpoint(&rpc, &deposit_funding_utxo_address, deposit_input_amount);
    let deposit_input = Input {
        outpoint: deposit_funding_outpoint,
        amount: deposit_input_amount,
    };

    let peg_in_deposit =
        PegInDepositTransaction::new(&depositor_context, &depositor_evm_address, deposit_input);
    let peg_in_deposit_tx = peg_in_deposit.finalize();
    let deposit_txid = peg_in_deposit_tx.compute_txid();
    // mine peg-in deposit
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &peg_in_deposit_tx);
    helper::mint_block(&rpc, 1);
    helper::validate_tx(&rpc, deposit_txid);

    // peg-in refund
    let output_index = 0;
    let refund_funding_outpoint = OutPoint {
        txid: deposit_txid,
        vout: output_index,
    };
    let refund_input = Input {
        outpoint: refund_funding_outpoint,
        amount: peg_in_deposit_tx.output[output_index as usize].value,
    };
    let peg_in_refund =
        PegInRefundTransaction::new(&depositor_context, &depositor_evm_address, refund_input);
    let peg_in_refund_tx = peg_in_refund.finalize();
    let refund_txid = peg_in_refund_tx.compute_txid();

    // mine peg-in refund
    sleep(Duration::from_secs(60)).await; // TODO: check if this can be refactored to drop waiting
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &peg_in_refund_tx);
    helper::mint_block(&rpc, 1);
    helper::validate_tx(&rpc, refund_txid);

    // check depositor balance
    // TODO
}
