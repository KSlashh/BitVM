use bitcoin::Amount;

use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    transactions::{
        base::{BaseTransaction, Input},
        peg_in_refund::PegInRefundTransaction,
    },
};

use super::super::{helper::{generate_stub_outpoint, self}, setup::setup_test};

#[tokio::test]
async fn test_peg_in_refund_tx() {
    let empty_script = vec![];
    let (
        rpc,
        depositor_context,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        connector_z,
        _,
        _,
        _,
        _,
        _,
        _,
        depositor_evm_address,
        _,
    ) = setup_test(&empty_script).await;

    let amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let outpoint =
        generate_stub_outpoint(&rpc, &connector_z.generate_taproot_address(), amount);

    let peg_in_refund_tx = PegInRefundTransaction::new(
        &depositor_context,
        &depositor_evm_address,
        Input { outpoint, amount },
    );

    let tx = peg_in_refund_tx.finalize();
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &tx);
    helper::mint_block(&rpc, 1);
    let txid = tx.compute_txid();
    println!("Txid: {:?}", txid.clone());
    helper::validate_tx(&rpc, txid);
}
