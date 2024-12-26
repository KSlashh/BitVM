use bitcoin::Amount;
use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::{DUST_AMOUNT, INITIAL_AMOUNT, HUGE_FEE_AMOUNT},
    transactions::{
        assert::AssertTransaction,
        base::{BaseTransaction, Input},
    },
    groth16::extract_signed_assertions_from_assert_tx,
};

use super::super::{
    helper::{generate_stub_outpoint, generate_stub_outpoint_batch, self}, 
    setup::{setup_test, get_bitcom_lock_scripts, get_bitcom_unlock_scripts, get_signed_assertions}
};

#[tokio::test]
async fn test_assert_tx() {
    let tap_scripts = vec![];
    let bitcom_scripts = get_bitcom_lock_scripts();
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
    ) = setup_test(&tap_scripts, &bitcom_scripts).await;
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

    let mut assert_tx = AssertTransaction::new(
        &operator_context, 
        input_0, 
        bitcom_inputs,
        connector_c, 
        revealers
    );
    assert_tx.push_bitcommitments_witness(get_bitcom_unlock_scripts());

    let tx = assert_tx.finalize();
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &tx);
    helper::mint_block(&rpc, 1);
    let txid = tx.compute_txid();
    println!("Txid: {:?}", txid.clone());
    let weight = tx.weight().to_wu();
    let fee_rate = 20;
    let fee_sat = weight * fee_rate / 4;
    let fee= (fee_sat as f64) / 1_000_000_000.0;
    println!("weight: {weight} WU, fee_rate: {fee_rate} sats/vB, fee: {fee} BTC, fee_sat: {fee_sat}");
    helper::validate_tx(&rpc, txid);

    let raw_sigs = get_signed_assertions();
    let raw_assert_tx = helper::get_raw_tx(&rpc, txid);
    let extract_sigs = extract_signed_assertions_from_assert_tx(raw_assert_tx);
    assert!(extract_sigs == raw_sigs);
}
