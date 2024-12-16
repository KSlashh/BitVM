
use bitcoin::{Amount, OutPoint};
use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::{DUST_AMOUNT, FEE_AMOUNT, HUGE_FEE_AMOUNT, INITIAL_AMOUNT, ONE_HUNDRED},
    transactions::{
        base::{BaseTransaction, Input},
        take_2::Take2Transaction,
    },
};
// use tokio::time::sleep;
// use std::time::Duration;

use crate::bridge::{
    helper,
    integration::peg_out::utils::{create_and_mine_assert_tx, create_and_mine_peg_in_confirm_tx},
    setup::{setup_test, get_bitcom_lock_scripts},
};

#[tokio::test]
async fn test_take_2_success() {
    let empty_script = vec![];
    let bitcom_lock_script = get_bitcom_lock_scripts();
    let (
        rpc,
        depositor_context,
        operator_context,
        verifier_0_context,
        verifier_1_context,
        _,
        _,
        connector_b,
        mut connector_c,
        connector_z,
        _,
        _,
        _,
        _,
        _,
        _,
        revealers,
        depositor_evm_address,
        _,
    ) = setup_test(&empty_script, &bitcom_lock_script).await;
    connector_c.gen_taproot_address();


    let deposit_input_amount = Amount::from_sat(ONE_HUNDRED);
    let peg_in_confirm_funding_address = connector_z.generate_taproot_address();

    let assert_input_amount = Amount::from_sat(INITIAL_AMOUNT + HUGE_FEE_AMOUNT + FEE_AMOUNT + 5*DUST_AMOUNT);
    let assert_funding_address = connector_b.generate_taproot_address();

    // peg-in confirm
    let (peg_in_confirm_tx, peg_in_confirm_txid) = create_and_mine_peg_in_confirm_tx(
        &rpc,
        &depositor_context,
        &verifier_0_context,
        &verifier_1_context,
        &depositor_evm_address,
        &peg_in_confirm_funding_address,
        deposit_input_amount,
    )
    .await;

    // assert
    let (assert_tx, assert_txid) = create_and_mine_assert_tx(
        &rpc,
        &operator_context,
        &assert_funding_address,
        assert_input_amount,
        connector_c.clone(),
        revealers,
    )
    .await;

    // take 2
    let vout = 0; // connector 0
    let take_2_input_0 = Input {
        outpoint: OutPoint {
            txid: peg_in_confirm_txid,
            vout,
        },
        amount: peg_in_confirm_tx.output[vout as usize].value,
    };
    let vout = 0; // connector 4
    let take_2_input_1 = Input {
        outpoint: OutPoint {
            txid: assert_txid,
            vout,
        },
        amount: assert_tx.output[vout as usize].value,
    };
    let vout = 1; // connector 5
    let take_2_input_2 = Input {
        outpoint: OutPoint {
            txid: assert_txid,
            vout,
        },
        amount: assert_tx.output[vout as usize].value,
    };
    let vout = 2; // connector c
    let take_2_input_3 = Input {
        outpoint: OutPoint {
            txid: assert_txid,
            vout,
        },
        amount: assert_tx.output[vout as usize].value,
    };

    let mut take_2 = Take2Transaction::new(
        &operator_context,
        connector_c,
        take_2_input_0,
        take_2_input_1,
        take_2_input_2,
        take_2_input_3,
    );

    let secret_nonces_0 = take_2.push_nonces(&verifier_0_context);
    let secret_nonces_1 = take_2.push_nonces(&verifier_1_context);

    take_2.pre_sign(&verifier_0_context, &secret_nonces_0);
    take_2.pre_sign(&verifier_1_context, &secret_nonces_1);

    let take_2_tx = take_2.finalize();
    let take_2_txid = take_2_tx.compute_txid();

    // mine take 2
    // sleep(Duration::from_secs(60)).await;
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &take_2_tx);
    helper::mint_block(&rpc, 1);
    helper::validate_tx(&rpc, take_2_txid);

    // operator balance check
    // TODO
}
