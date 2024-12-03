use bitcoin::Amount;

use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::{HUGE_FEE_AMOUNT, INITIAL_AMOUNT},
    transactions::{
        base::{BaseTransaction, Input},
        kick_off_2::KickOff2Transaction,
    },
};

use super::super::{helper::{generate_stub_outpoint, self}, setup::setup_test};

#[tokio::test]
async fn test_kick_off_2_tx() {
    let empty_script = vec![];
    let (rpc, _, operator_context, _, _, _, _, _, _, _, _, connector_1, _, _, _, _, _, _) =
        setup_test(&empty_script).await;

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
    );

    let tx = kick_off_2_tx.finalize();
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &tx);
    helper::mint_block(&rpc, 1);
    let txid = tx.compute_txid();
    println!("Txid: {:?}", txid.clone());
    helper::validate_tx(&rpc, txid);
}
