use bitcoin::Amount;

use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::{DUST_AMOUNT, ONE_HUNDRED},
    transactions::{
        base::{BaseTransaction, Input},
        start_time_timeout::StartTimeTimeoutTransaction,
    },
};

use super::super::{helper::{generate_stub_outpoint, self}, setup::setup_test};

#[tokio::test]
async fn test_start_time_timeout_tx() {
    let empty_script = vec![];
    let (
        rpc,
        _,
        operator_context,
        verifier_0_context,
        verifier_1_context,
        _,
        _,
        _,
        _,
        _,
        _,
        connector_1,
        connector_2,
        _,
        _,
        _,
        _,
        _,
        _,
    ) = setup_test(&empty_script, &empty_script).await;

    let input_value0 = Amount::from_sat(DUST_AMOUNT);
    let funding_utxo_address0 = connector_2.generate_taproot_address();
    let funding_outpoint0 =
        generate_stub_outpoint(&rpc, &funding_utxo_address0, input_value0);

    let input_value1 = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let funding_utxo_address1 = connector_1.generate_taproot_address();
    let funding_outpoint1 =
        generate_stub_outpoint(&rpc, &funding_utxo_address1, input_value1);

    let mut start_time_timeout_tx = StartTimeTimeoutTransaction::new(
        &operator_context,
        Input {
            outpoint: funding_outpoint0,
            amount: input_value0,
        },
        Input {
            outpoint: funding_outpoint1,
            amount: input_value1,
        },
    );

    let secret_nonces_0 = start_time_timeout_tx.push_nonces(&verifier_0_context);
    let secret_nonces_1 = start_time_timeout_tx.push_nonces(&verifier_1_context);

    start_time_timeout_tx.pre_sign(&verifier_0_context, &secret_nonces_0);
    start_time_timeout_tx.pre_sign(&verifier_1_context, &secret_nonces_1);

    let tx = start_time_timeout_tx.finalize();
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
