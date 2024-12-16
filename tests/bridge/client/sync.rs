#![allow(dead_code, unused_imports)]
use bitcoin::Amount;

use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::base::Input,
};

use super::super::{helper::generate_stub_outpoint, setup::{setup_test, new_client}};

// #[tokio::test]
async fn test_sync() {
    let empty_scripts = vec![];
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
    ) = setup_test(&empty_scripts, &empty_scripts).await;
    let (mut client, _) = new_client().await;

    println!("Read from remote");
    client.sync().await;

    println!("Modify data and save");
    let amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT + 1);
    let outpoint = generate_stub_outpoint(
        &rpc,
        &generate_pay_to_pubkey_script_address(
            depositor_context.network,
            &depositor_context.depositor_public_key,
        ),
        amount,
    );

    let peg_in_graph_id = client
        .create_peg_in_graph(Input { outpoint, amount }, &depositor_evm_address)
        .await;

    client
        .create_peg_out_graph(
            &peg_in_graph_id,
            Input {
                outpoint: generate_stub_outpoint(
                    &rpc,
                    &generate_pay_to_pubkey_script_address(
                        depositor_context.network,
                        &depositor_context.depositor_public_key,
                    ),
                    amount,
                ),
                amount,
            },
            &empty_scripts,
            &empty_scripts,
        )
        .await;

    println!("Save to remote");
    client.flush().await;
}
