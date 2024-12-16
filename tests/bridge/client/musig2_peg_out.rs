#![allow(dead_code, unused_imports)]
use std::time::Duration;

use bitcoin::{Address, Amount};
use bitcoincore_rpc::Client;
use bitvm::treepp::*;
use bitvm::bridge::{
    client::client::BitVMClient,
    contexts::depositor::DepositorContext,
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::{generate_pay_to_pubkey_script, generate_pay_to_pubkey_script_address},
    transactions::base::{Input, InputWithScript},
};
use tokio::time::sleep;

use crate::bridge::{
    helper::{generate_stub_outpoint, TX_WAIT_TIME},
    setup::{setup_test, new_client},
};

// #[tokio::test]
async fn test_musig2_peg_out_take_1() {
    let empty_scripts = vec![];
    let with_kick_off_2_tx = false;
    let with_challenge_tx = false;
    let with_assert_tx = false;
    let (mut depositor_operator_verifier_0_client, _, peg_out_graph_id, _) =
        create_peg_out_graph(&empty_scripts, &empty_scripts, with_kick_off_2_tx, with_challenge_tx, with_assert_tx).await;

    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_take_1(&peg_out_graph_id)
        .await;
}

// #[tokio::test]
async fn test_musig2_peg_out_take_2() {
    let empty_scripts = vec![];
    let with_kick_off_2_tx = true;
    let with_challenge_tx = false;
    let with_assert_tx = true;
    let (mut depositor_operator_verifier_0_client, _, peg_out_graph_id, _) =
        create_peg_out_graph(&empty_scripts, &empty_scripts, with_kick_off_2_tx, with_challenge_tx, with_assert_tx).await;

    eprintln!("Broadcasting take 2...");
    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_take_2(&peg_out_graph_id)
        .await;
}

// #[tokio::test]
async fn test_musig2_start_time_timeout() {
    let empty_scripts = vec![];
    let with_kick_off_2_tx = false;
    let with_challenge_tx = false;
    let with_assert_tx = false;
    let (mut depositor_operator_verifier_0_client, _, peg_out_graph_id, depositor_context) =
        create_peg_out_graph(&empty_scripts, &empty_scripts, with_kick_off_2_tx, with_challenge_tx, with_assert_tx).await;

    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_start_time_timeout(
            &peg_out_graph_id,
            generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
        )
        .await;
}

// #[tokio::test]
async fn test_musig2_kick_off_timeout() {
    let empty_scripts = vec![];
    let with_kick_off_2_tx = false;
    let with_challenge_tx = false;
    let with_assert_tx = false;
    let (mut depositor_operator_verifier_0_client, _, peg_out_graph_id, depositor_context) =
        create_peg_out_graph(&empty_scripts, &empty_scripts, with_kick_off_2_tx, with_challenge_tx, with_assert_tx).await;

    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_kick_off_timeout(
            &peg_out_graph_id,
            generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
        )
        .await;
}

// #[tokio::test]
// async fn test_musig2_peg_out_disprove_with_challenge() {
//     let with_kick_off_2_tx = true;
//     let with_challenge_tx = true;
//     let with_assert_tx = true;
//     let (mut depositor_operator_verifier_0_client, _, peg_out_graph_id, depositor_context) =
//         create_peg_out_graph(with_kick_off_2_tx, with_challenge_tx, with_assert_tx).await;

//     depositor_operator_verifier_0_client.sync().await;
//     depositor_operator_verifier_0_client
//         .broadcast_disprove(
//             &peg_out_graph_id,
//             1,
//             generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
//         )
//         .await;
// }

// #[tokio::test]
async fn test_musig2_peg_out_disprove_chain_with_challenge() {
    let empty_scripts = vec![];
    let with_kick_off_2_tx = true;
    let with_challenge_tx = true;
    let with_assert_tx = false;
    let (mut depositor_operator_verifier_0_client, _, peg_out_graph_id, depositor_context) =
        create_peg_out_graph(&empty_scripts, &empty_scripts, with_kick_off_2_tx, with_challenge_tx, with_assert_tx).await;

    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_disprove_chain(
            &peg_out_graph_id,
            generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
        )
        .await;
}

async fn create_peg_out_graph<'a>(
    tap_scripts: &'a Vec<Script>,
    bitcom_lock_scripts: &'a Vec<Script>,
    with_kick_off_2_tx: bool,
    with_challenge_tx: bool,
    with_assert_tx: bool,
) -> (BitVMClient<'a>, BitVMClient<'a>, String, DepositorContext) {
    let (
        rpc,
        depositor_context,
        operator_context,
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
    ) = setup_test(tap_scripts, bitcom_lock_scripts).await;
    let (mut depositor_operator_verifier_0_client, mut verifier_1_client) = new_client().await;


    let deposit_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let deposit_funding_address = generate_pay_to_pubkey_script_address(
        depositor_context.network,
        &depositor_context.depositor_public_key,
    );

    let kick_off_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let kick_off_funding_utxo_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );

    let challenge_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let challenge_funding_utxo_address = generate_pay_to_pubkey_script_address(
        depositor_context.network,
        &depositor_context.depositor_public_key,
    );

    let kick_off_outpoint = generate_stub_outpoint(
        &rpc,
        &kick_off_funding_utxo_address,
        kick_off_input_amount,
    );

    eprintln!("Creating peg-in graph...");
    // create and complete peg-in graph
    let peg_in_graph_id = create_peg_in_graph(
        &rpc,
        &mut depositor_operator_verifier_0_client,
        &mut verifier_1_client,
        deposit_funding_address,
        deposit_input_amount,
        &depositor_evm_address,
    )
    .await;

    eprintln!("Creating peg-out graph...");
    depositor_operator_verifier_0_client.sync().await;
    let peg_out_graph_id = depositor_operator_verifier_0_client
        .create_peg_out_graph(
            &peg_in_graph_id,
            Input {
                outpoint: kick_off_outpoint,
                amount: kick_off_input_amount,
            },
            tap_scripts,
            &bitcom_lock_scripts,
        )
        .await;

    eprintln!("Verifier 0 push peg-out nonces");
    depositor_operator_verifier_0_client.push_peg_out_nonces(&peg_out_graph_id);
    depositor_operator_verifier_0_client.flush().await;

    eprintln!("Verifier 1 push peg-out nonces");
    verifier_1_client.sync().await;
    verifier_1_client.push_peg_out_nonces(&peg_out_graph_id);
    verifier_1_client.flush().await;

    eprintln!("Verifier 0 pre-sign peg-out");
    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client.pre_sign_peg_out(&peg_out_graph_id);
    depositor_operator_verifier_0_client.flush().await;

    eprintln!("Verifier 1 pre-sign peg-out");
    verifier_1_client.sync().await;
    verifier_1_client.pre_sign_peg_out(&peg_out_graph_id);
    verifier_1_client.flush().await;

    eprintln!("Broadcasting kick-off 1...");
    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_kick_off_1(&peg_out_graph_id)
        .await;

    // Wait for peg-in deposit transaction to be mined
    println!("Waiting for peg-out kick-off tx...");
    sleep(Duration::from_secs(TX_WAIT_TIME)).await;

    if with_kick_off_2_tx {
        eprintln!("Broadcasting start time...");
        depositor_operator_verifier_0_client
            .broadcast_start_time(&peg_out_graph_id)
            .await;

        println!("Waiting for peg-out start time tx...");
        sleep(Duration::from_secs(TX_WAIT_TIME)).await;

        eprintln!("Broadcasting kick-off 2...");
        depositor_operator_verifier_0_client
            .broadcast_kick_off_2(&peg_out_graph_id)
            .await;

        println!("Waiting for peg-out kick-off 2 tx...");
        sleep(Duration::from_secs(TX_WAIT_TIME)).await;
    }

    if with_challenge_tx {
        let challenge_funding_outpoint = generate_stub_outpoint(
            &rpc,
            &challenge_funding_utxo_address,
            challenge_input_amount,
        );
        let challenge_crowdfunding_input = InputWithScript {
            outpoint: challenge_funding_outpoint,
            amount: challenge_input_amount,
            script: &generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
        };
        eprintln!("Broadcasting challenge...");
        depositor_operator_verifier_0_client
            .broadcast_challenge(
                &peg_out_graph_id,
                &vec![challenge_crowdfunding_input],
                generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
            )
            .await;

        println!("Waiting for peg-out challenge tx...");
        sleep(Duration::from_secs(TX_WAIT_TIME)).await;
    }

    if with_assert_tx {
        eprintln!("Broadcasting assert...");
        depositor_operator_verifier_0_client
            .broadcast_assert(&peg_out_graph_id)
            .await;

        println!("Waiting for peg-out assert tx...");
        sleep(Duration::from_secs(TX_WAIT_TIME)).await;
    }

    return (
        depositor_operator_verifier_0_client,
        verifier_1_client,
        peg_out_graph_id,
        depositor_context,
    );
}

async fn create_peg_in_graph<'a>(
    rpc: &Client,
    client_0: &mut BitVMClient<'a>,
    client_1: &mut BitVMClient<'a>,
    deposit_funding_address: Address,
    deposit_amount: Amount,
    depositor_evm_address: &String,
) -> String {
    let deposit_outpoint =
        generate_stub_outpoint(rpc, &deposit_funding_address, deposit_amount);
    let graph_id = client_0
        .create_peg_in_graph(
            Input {
                outpoint: deposit_outpoint,
                amount: deposit_amount,
            },
            depositor_evm_address,
        )
        .await;

    client_0.broadcast_peg_in_deposit(&graph_id).await;
    client_0.push_peg_in_nonces(&graph_id);
    client_0.flush().await;

    client_1.sync().await;
    client_1.push_peg_in_nonces(&graph_id);
    client_1.flush().await;

    client_0.sync().await;
    client_0.pre_sign_peg_in(&graph_id);
    client_0.flush().await;

    client_1.sync().await;
    client_1.pre_sign_peg_in(&graph_id);
    client_1.flush().await;

    // Wait for peg-in deposit transaction to be mined
    println!("Waiting for peg-in deposit tx...");
    sleep(Duration::from_secs(TX_WAIT_TIME)).await;

    client_0.sync().await;
    client_0.broadcast_peg_in_confirm(&graph_id).await;
    client_0.flush().await;

    return graph_id;
}
