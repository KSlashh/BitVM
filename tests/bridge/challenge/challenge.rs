use bitcoin::{Amount, OutPoint};
use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::{DUST_AMOUNT, INITIAL_AMOUNT},
    scripts::{generate_pay_to_pubkey_script, generate_pay_to_pubkey_script_address},
    transactions::{
        base::{BaseTransaction, Input, InputWithScript},
        challenge::ChallengeTransaction,
    },
};

use crate::bridge::helper::{self, fund_utxo, generate_stub_outpoint};

use crate::bridge::setup::setup_test;

#[tokio::test]
async fn test_challenge_tx() {
    let empty_script = vec![];
    let (
        rpc,
        depositor_context,
        operator_context,
        _,
        _,
        _,
        connector_a,
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
    ) = setup_test(&empty_script).await;

    // We re-use the depositor private key to imitate a third-party
    let crowdfunding_keypair = &depositor_context.depositor_keypair;
    let crowdfunding_public_key = &depositor_context.depositor_public_key;

    let amount_0 = Amount::from_sat(DUST_AMOUNT);
    let outpoint_0 =
        generate_stub_outpoint(&rpc, &connector_a.generate_taproot_address(), amount_0);

    // Create two inputs that exceed the crowdfunding total
    let input_amount_crowdfunding_total = Amount::from_sat(INITIAL_AMOUNT);

    let address =
        generate_pay_to_pubkey_script_address(depositor_context.network, crowdfunding_public_key);
    let amount_1 = Amount::from_sat(INITIAL_AMOUNT);

    // Check there are two utxos
    let crowdfunding_utxos = [
        fund_utxo(&rpc, &address, amount_1),
    ];


    let refund_address =
        generate_pay_to_pubkey_script_address(depositor_context.network, crowdfunding_public_key);

    let mut challenge_tx = ChallengeTransaction::new(
        &operator_context,
        Input {
            outpoint: outpoint_0,
            amount: amount_0,
        },
        input_amount_crowdfunding_total,
    );

    challenge_tx.add_inputs_and_output(
        &depositor_context,
        &vec![
            InputWithScript {
                outpoint: OutPoint {
                    txid: crowdfunding_utxos[0].txid,
                    vout: crowdfunding_utxos[0].vout,
                },
                amount: amount_1,
                script: &generate_pay_to_pubkey_script(crowdfunding_public_key),
            },
        ],
        crowdfunding_keypair,
        refund_address.script_pubkey(),
    );

    let tx = challenge_tx.finalize();
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

