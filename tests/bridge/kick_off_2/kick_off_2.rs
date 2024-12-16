use bitcoin::Amount;
use bitvm::treepp::*;
use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::{HUGE_FEE_AMOUNT, INITIAL_AMOUNT},
    transactions::{
        base::{BaseTransaction, Input},
        kick_off_2::KickOff2Transaction,
    },
};

use super::super::{helper::{generate_stub_outpoint, self}, setup::{setup_test, get_bitcom_lock_scripts}};

#[tokio::test]
async fn test_kick_off_2_tx() {
    let empty_script: Vec<Script> = vec![];
    let bitcom_lock_scripts = get_bitcom_lock_scripts();
    let (rpc, _, operator_context, _, _, _, _, _, _, _, _, connector_1, _, _, _, _, revealers, _, _) =
        setup_test(&empty_script, &bitcom_lock_scripts).await;

    let input_value0 = Amount::from_sat(INITIAL_AMOUNT + HUGE_FEE_AMOUNT);
    let funding_utxo_address0 = connector_1.generate_taproot_address();
    let funding_outpoint0 =
        generate_stub_outpoint(&rpc, &funding_utxo_address0, input_value0);

    let kick_off_2_tx = KickOff2Transaction::new(
        &operator_context,
        Input {
            outpoint: funding_outpoint0,
            amount: input_value0,
        },
        revealers,
    );

    let tx = kick_off_2_tx.finalize();
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
}
