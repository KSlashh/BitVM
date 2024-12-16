#![allow(dead_code, unused_imports)]
use bitcoin::Amount;

use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::{DUST_AMOUNT, HUGE_FEE_AMOUNT, INITIAL_AMOUNT, ONE_HUNDRED},
    serialization::{deserialize, serialize},
    transactions::{assert::AssertTransaction, base::Input},
};

use super::super::{helper::{generate_stub_outpoint, generate_stub_outpoint_batch}, setup::setup_test};

// #[tokio::test]s
async fn test_assert_tx_serialization() {
    let empty_scripts = vec![];
    let (
        rpc,
        _,
        operator_context,
        _,
        _,
        _,
        _,
        connector_b,
        mut connector_c,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        revealers,
        _,
        _,
    ) = setup_test(&empty_scripts, &empty_scripts).await;
    connector_c.gen_taproot_address();

    let amount = Amount::from_sat(INITIAL_AMOUNT + HUGE_FEE_AMOUNT + 2*DUST_AMOUNT);
    let outpoint_0 = generate_stub_outpoint(&rpc, &connector_b.generate_taproot_address(), amount);
    let input_0 = Input { outpoint: outpoint_0, amount };

    let revealer_num = revealers.len();
    let bitcom_utxo_amount = Amount::from_sat(DUST_AMOUNT);
    let bitcom_utxo_addresses = revealers.iter().map(|revealer| revealer.generate_taproot_address()).collect();
    let bitcom_utxo_amounts = vec![bitcom_utxo_amount; revealer_num];
    let bitcom_outpoint = generate_stub_outpoint_batch(&rpc, &bitcom_utxo_addresses, &bitcom_utxo_amounts);
    let bitcom_inputs = bitcom_outpoint.iter().map(|outpoint| Input { outpoint: *outpoint, amount: bitcom_utxo_amount }).collect();

    let assert_tx = AssertTransaction::new(
        &operator_context, 
        input_0, 
        bitcom_inputs,
        connector_c, 
        revealers
    );
    let json = serialize(&assert_tx);
    assert!(json.len() > 0);
    let _deserialized_assert_tx = deserialize::<AssertTransaction>(&json);
    // TODO: serialization & deserialization
    // assert!(assert_tx == deserialized_assert_tx);
}
