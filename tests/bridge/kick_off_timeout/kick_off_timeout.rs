use bitcoin::Amount;

use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::ONE_HUNDRED,
    transactions::{
        base::{BaseTransaction, Input},
        kick_off_timeout::KickOffTimeoutTransaction,
    },
};

use super::super::{helper::{generate_stub_outpoint, self}, setup::setup_test};

#[tokio::test]
async fn test_kick_off_timeout_tx() {
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
        _,
        _,
        _,
        _,
        _,
        _,
    ) = setup_test(&empty_script).await;

    let input_value0 = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let outpoint_0 = generate_stub_outpoint(
        &rpc,
        &connector_1.generate_taproot_address(),
        input_value0,
    );

    let mut kick_off_timeout_tx = KickOffTimeoutTransaction::new(
        &operator_context,
        Input {
            outpoint: outpoint_0,
            amount: input_value0,
        },
    );

    let secret_nonces_0 = kick_off_timeout_tx.push_nonces(&verifier_0_context);
    let secret_nonces_1 = kick_off_timeout_tx.push_nonces(&verifier_1_context);

    kick_off_timeout_tx.pre_sign(&verifier_0_context, &secret_nonces_0);
    kick_off_timeout_tx.pre_sign(&verifier_1_context, &secret_nonces_1);

    let tx = kick_off_timeout_tx.finalize();
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
