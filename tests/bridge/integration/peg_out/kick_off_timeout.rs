use std::time::Duration;
use tokio::time::sleep;

use bitcoin::{Amount, OutPoint};
use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        kick_off_timeout::KickOffTimeoutTransaction,
    },
};

use crate::bridge::{
    helper, integration::peg_out::utils::create_and_mine_kick_off_1_tx,
    setup::setup_test,
};

#[tokio::test]
async fn test_kick_off_timeout_success() {
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
    )
    .await;

    // kick-off timeout
    let vout = 1; // connector 1
    let kick_off_timeout_input_0 = Input {
        outpoint: OutPoint {
            txid: kick_off_1_txid,
            vout: vout,
        },
        amount: kick_off_1_tx.output[vout as usize].value,
    };

    let mut kick_off_timeout =
        KickOffTimeoutTransaction::new(&operator_context, kick_off_timeout_input_0);

    let secret_nonces_0 = kick_off_timeout.push_nonces(&verifier_0_context);
    let secret_nonces_1 = kick_off_timeout.push_nonces(&verifier_1_context);

    kick_off_timeout.pre_sign(&verifier_0_context, &secret_nonces_0);
    kick_off_timeout.pre_sign(&verifier_1_context, &secret_nonces_1);

    let reward_address = generate_pay_to_pubkey_script_address(
        withdrawer_context.network,
        &withdrawer_context.withdrawer_public_key,
    );
    kick_off_timeout.add_output(reward_address.script_pubkey());

    let kick_off_timeout_tx = kick_off_timeout.finalize();
    let kick_off_timeout_txid = kick_off_timeout_tx.compute_txid();

    // mine kick-off timeout
    sleep(Duration::from_secs(60)).await;
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &kick_off_timeout_tx);
    helper::mint_block(&rpc, 1);
    helper::validate_tx(&rpc, kick_off_timeout_txid);

    // reward balance check
    // TODO
}
