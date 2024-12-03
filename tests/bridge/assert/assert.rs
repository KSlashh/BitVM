use bitcoin::Amount;
use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::{DUST_AMOUNT, INITIAL_AMOUNT, LARGE_FEE_AMOUNT},
    transactions::{
        assert::AssertTransaction,
        base::{BaseTransaction, Input},
    },
};

use super::super::{helper::{generate_stub_outpoint, self}, setup::setup_test};

#[tokio::test]
async fn test_assert_tx() {
    let tap_scripts = vec![];
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
        _,
        _,
    ) = setup_test(&tap_scripts).await;
    connector_c.gen_taproot_address();

    let amount = Amount::from_sat(INITIAL_AMOUNT + LARGE_FEE_AMOUNT + 2*DUST_AMOUNT);
    let outpoint = generate_stub_outpoint(&rpc, &connector_b.generate_taproot_address(), amount);

    let assert_tx = AssertTransaction::new(&operator_context, Input { outpoint, amount }, connector_c);
    let tx = assert_tx.finalize();
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &tx);
    helper::mint_block(&rpc, 1);
    let txid = tx.compute_txid();
    println!("Txid: {:?}", txid.clone());
    helper::validate_tx(&rpc, txid);
}
