use bitcoin::Amount;

use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT, WITHDRAWER_EVM_ADDRESS},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        peg_out::PegOutTransaction,
    },
};

use crate::bridge::{
    helper::{generate_stub_outpoint, self},
    setup::setup_test,
};

#[tokio::test]
async fn test_peg_out_for_chain() {
    let empty_script = vec![];
    let (
        rpc,
        _,
        operator_context,
        _,
        _,
        withdrawer_context,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
    ) = setup_test(&empty_script, &empty_script).await;

    let input_amount_raw = INITIAL_AMOUNT + FEE_AMOUNT;
    let operator_input_amount = Amount::from_sat(input_amount_raw);

    let operator_funding_utxo_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );

    let operator_funding_outpoint = generate_stub_outpoint(
        &rpc,
        &operator_funding_utxo_address,
        operator_input_amount,
    );
    let operator_input = Input {
        outpoint: operator_funding_outpoint,
        amount: operator_input_amount,
    };

    let peg_out = PegOutTransaction::new(
        &operator_context,
        &withdrawer_context.withdrawer_public_key,
        WITHDRAWER_EVM_ADDRESS,
        0,
        operator_input,
    );

    let peg_out_tx = peg_out.finalize();
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &peg_out_tx);
    helper::mint_block(&rpc, 1);
    let txid = peg_out_tx.compute_txid();
    println!("Txid: {:?}", txid.clone());
    helper::validate_tx(&rpc, txid);
}
