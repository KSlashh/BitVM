use bitcoin::{consensus::encode::serialize_hex, Amount};

use bitvm::bridge::{
    connectors::{connector::TaprootConnector, connector_4},
    graphs::base::ONE_HUNDRED,
    transactions::{
        assert::AssertTransaction,
        base::{BaseTransaction, Input},
    },
    groth16::load_assert_tapscripts_from_file,
};

use bitvm::groth16::g16;

use super::super::{helper::generate_stub_outpoint, setup::{setup_test, get_tapscripts}};

#[tokio::test]
async fn test_assert_tx() {
    let tap_scripts = get_tapscripts();
    let (
        client,
        _,
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

    let amount = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let outpoint =
        generate_stub_outpoint(&client, &connector_b.generate_taproot_address(), amount).await;

    let assert_tx = AssertTransaction::new(&operator_context, Input { outpoint, amount }, connector_c);

    let tx = assert_tx.finalize();
    // println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = client.esplora.broadcast(&tx).await;
    println!("\nTxid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    // println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
