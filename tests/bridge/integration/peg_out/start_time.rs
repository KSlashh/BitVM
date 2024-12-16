use bitcoin::{Amount, OutPoint};
use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        start_time::StartTimeTransaction,
    },
};

use crate::bridge::{
    helper, integration::peg_out::utils::create_and_mine_kick_off_1_tx,
    setup::setup_test,
};

#[tokio::test]
async fn test_start_time_success() {
    let empty_script = vec![];
    let (rpc, _, operator_context, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _) =
        setup_test(&empty_script, &empty_script).await;

    let kick_off_1_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let kick_off_1_funding_utxo_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );

    // kick-off 1
    let (kick_off_1_tx, kick_off_1_txid) = create_and_mine_kick_off_1_tx(
        &rpc,
        &operator_context,
        &kick_off_1_funding_utxo_address,
        kick_off_1_input_amount,
    )
    .await;

    // start time
    let vout = 2;
    let start_time_input_0 = Input {
        outpoint: OutPoint {
            // connector 2
            txid: kick_off_1_txid,
            vout,
        },
        amount: kick_off_1_tx.output[vout as usize].value,
    };
    let start_time = StartTimeTransaction::new(&operator_context, start_time_input_0);
    let start_time_tx = start_time.finalize();

    // mine start time
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &start_time_tx);
    helper::mint_block(&rpc, 1);
    let txid = start_time_tx.compute_txid();
    helper::validate_tx(&rpc, txid);
}
