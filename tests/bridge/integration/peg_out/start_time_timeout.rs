use std::time::Duration;
use tokio::time::sleep;

use bitcoin::{Amount, OutPoint};
use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        start_time_timeout::StartTimeTimeoutTransaction,
    },
};

use crate::bridge::{
    helper, integration::peg_out::utils::create_and_mine_kick_off_1_tx,
    setup::setup_test,
};

#[tokio::test]
async fn test_start_time_timeout_success() {
    let empty_script = vec![];
    let (
        rpc,
        _,
        operator_context,
        verifier_0_context,
        verifier_1_context,
        withdrawer_context,
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
    ) = setup_test(&empty_script, &empty_script).await;

    // verify funding inputs
    let kick_off_1_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let kick_off_1_funding_utxo_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );

    // kick-off 1
    let (kick_off_1_tx, kick_off_1_txid) = create_and_mine_kick_off_1_tx(
        &rpc,
        &operator_context,
        &kick_off_1_funding_utxo_address,
        kick_off_1_input_amount,
    ).await;

    // start time timeout
    let vout = 2; // connector 2
    let start_time_timeout_input_0 = Input {
        outpoint: OutPoint {
            txid: kick_off_1_txid,
            vout,
        },
        amount: kick_off_1_tx.output[vout as usize].value,
    };
    let vout = 1; // connector 1
    let start_time_timeout_input_1 = Input {
        outpoint: OutPoint {
            txid: kick_off_1_txid,
            vout,
        },
        amount: kick_off_1_tx.output[vout as usize].value,
    };
    let mut start_time_timeout = StartTimeTimeoutTransaction::new(
        &operator_context,
        start_time_timeout_input_0,
        start_time_timeout_input_1,
    );

    let secret_nonces_0 = start_time_timeout.push_nonces(&verifier_0_context);
    let secret_nonces_1 = start_time_timeout.push_nonces(&verifier_1_context);

    start_time_timeout.pre_sign(&verifier_0_context, &secret_nonces_0);
    start_time_timeout.pre_sign(&verifier_1_context, &secret_nonces_1);

    let reward_address = generate_pay_to_pubkey_script_address(
        withdrawer_context.network,
        &withdrawer_context.withdrawer_public_key,
    );
    start_time_timeout.add_output(reward_address.script_pubkey());

    let start_time_timeout_tx = start_time_timeout.finalize();
    let start_time_timeout_txid = start_time_timeout_tx.compute_txid();

    // mine start time timeout
    sleep(Duration::from_secs(60)).await;
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &start_time_timeout_tx);
    helper::mint_block(&rpc, 1);
    helper::validate_tx(&rpc, start_time_timeout_txid);

    // reward balance check
    // TODO
}
