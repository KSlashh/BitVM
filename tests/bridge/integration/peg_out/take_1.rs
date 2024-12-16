use bitcoin::{Amount, OutPoint};
use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::{DUST_AMOUNT, FEE_AMOUNT, HUGE_FEE_AMOUNT, INITIAL_AMOUNT, ONE_HUNDRED},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        kick_off_2::KickOff2Transaction,
        take_1::Take1Transaction,
    },
};
// use tokio::time::sleep;
// use std::time::Duration;

use crate::bridge::{
    helper,
    integration::peg_out::utils::{
        create_and_mine_kick_off_1_tx, create_and_mine_peg_in_confirm_tx,
    },
    setup::{get_bitcom_lock_scripts, setup_test},
};

#[tokio::test]
async fn test_take_1_success() {
    let empty_script = vec![];
    let bitcom_lock_scripts = get_bitcom_lock_scripts();
    let (
        rpc,
        depositor_context,
        operator_context,
        verifier_0_context,
        verifier_1_context,
        _,
        _,
        _,
        _,
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
    ) = setup_test(&empty_script, &bitcom_lock_scripts).await;

    let deposit_input_amount = Amount::from_sat(ONE_HUNDRED);
    let peg_in_confirm_funding_address = connector_z.generate_taproot_address();

    let kick_off_1_input_amount = Amount::from_sat(INITIAL_AMOUNT + 2*HUGE_FEE_AMOUNT + FEE_AMOUNT + 3*DUST_AMOUNT);
    let kick_off_1_funding_utxo_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );

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

    // kick-off 1
    let (kick_off_1_tx, kick_off_1_txid) = create_and_mine_kick_off_1_tx(
        &rpc,
        &operator_context,
        &kick_off_1_funding_utxo_address,
        kick_off_1_input_amount,
    )
    .await;

    // kick-off 2
    let vout = 1; // connector 1
    let kick_off_2_input_0 = Input {
        outpoint: OutPoint {
            txid: kick_off_1_txid,
            vout,
        },
        amount: kick_off_1_tx.output[vout as usize].value,
    };
    let kick_off_2 = KickOff2Transaction::new(&operator_context, kick_off_2_input_0, revealers);
    let kick_off_2_tx = kick_off_2.finalize();
    let kick_off_2_txid = kick_off_2_tx.compute_txid();

    // mine kick-off 2
    // sleep(Duration::from_secs(60)).await;
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &kick_off_2_tx);
    helper::mint_block(&rpc, 1);
    helper::validate_tx(&rpc, kick_off_2_txid);

    // take 1
    let vout = 0; // connector 0
    let take_1_input_0 = Input {
        outpoint: OutPoint {
            txid: peg_in_confirm_txid,
            vout,
        },
        amount: peg_in_confirm_tx.output[vout as usize].value,
    };
    let vout = 0; // connector a
    let take_1_input_1 = Input {
        outpoint: OutPoint {
            txid: kick_off_1_txid,
            vout,
        },
        amount: kick_off_1_tx.output[vout as usize].value,
    };
    let vout = 0; // connector 3
    let take_1_input_2 = Input {
        outpoint: OutPoint {
            txid: kick_off_2_txid,
            vout,
        },
        amount: kick_off_2_tx.output[vout as usize].value,
    };
    let vout = 1; // connector b
    let take_1_input_3 = Input {
        outpoint: OutPoint {
            txid: kick_off_2_txid,
            vout,
        },
        amount: kick_off_2_tx.output[vout as usize].value,
    };

    let mut take_1 = Take1Transaction::new(
        &operator_context,
        take_1_input_0,
        take_1_input_1,
        take_1_input_2,
        take_1_input_3,
    );

    let secret_nonces_0 = take_1.push_nonces(&verifier_0_context);
    let secret_nonces_1 = take_1.push_nonces(&verifier_1_context);

    take_1.pre_sign(&verifier_0_context, &secret_nonces_0);
    take_1.pre_sign(&verifier_1_context, &secret_nonces_1);

    let take_1_tx = take_1.finalize();
    let take_1_txid = take_1_tx.compute_txid();

    // mine take 1
    // sleep(Duration::from_secs(60)).await;
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &take_1_tx);
    helper::mint_block(&rpc, 1);
    helper::validate_tx(&rpc, take_1_txid);

    // operator balance check 
    // TODO
}
