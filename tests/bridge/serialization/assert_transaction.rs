use bitcoin::Amount;

use bitvm::bridge::{
    connectors::{connector::TaprootConnector, connector_c::ConnectorC},
    graphs::base::ONE_HUNDRED,
    serialization::{deserialize, serialize},
    transactions::{assert::AssertTransaction, base::Input},
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_assert_tx_serialization() {
    let empty_scripts = vec![];
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
    ) = setup_test(&empty_scripts).await;
    connector_c.gen_taproot_address();

    let amount = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let outpoint =
        generate_stub_outpoint(&client, &connector_b.generate_taproot_address(), amount).await;

    let assert_tx = AssertTransaction::new(&operator_context, Input { outpoint, amount }, connector_c);

    let json = serialize(&assert_tx);
    assert!(json.len() > 0);
    let deserialized_assert_tx = deserialize::<AssertTransaction>(&json);
    // TODO: serialization & deserialization
    // assert!(assert_tx == deserialized_assert_tx);
}
