use bitcoin::Amount;

use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        kick_off_1::KickOff1Transaction,
    },
};

use crate::bridge::helper::{generate_stub_outpoint, self};

use super::super::setup::setup_test;

#[tokio::test]
async fn test_kick_off_1_tx() {
    let empty_script = vec![];
    let (rpc, _, operator_context, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _) =
        setup_test(&empty_script, &empty_script).await;

    let input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let funding_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );
    let funding_outpoint_0 = generate_stub_outpoint(&rpc, &funding_address, input_amount);

    let input = Input {
        outpoint: funding_outpoint_0,
        amount: input_amount,
    };

    let kick_off_1_tx = KickOff1Transaction::new(&operator_context, input);

    let tx = kick_off_1_tx.finalize();
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
