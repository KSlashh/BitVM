use bitcoin::{Amount, OutPoint};

use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::{generate_pay_to_pubkey_script, generate_pay_to_pubkey_script_address},
    transactions::{
        base::{BaseTransaction, Input, InputWithScript},
        challenge::ChallengeTransaction,
    },
};

use crate::bridge::{
    helper::{generate_stub_outpoint, self},
    integration::peg_out::utils::create_and_mine_kick_off_1_tx,
    setup::setup_test,
};

#[tokio::test]
async fn test_challenge_success() {
    let empty_script = vec![];
    let (
        rpc,
        depositor_context,
        operator_context,
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
        _,
        _,
    ) = setup_test(&empty_script).await;

    let kick_off_1_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let kick_off_1_funding_utxo_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );

    let challenge_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let challenge_funding_utxo_address = generate_pay_to_pubkey_script_address(
        depositor_context.network,
        &depositor_context.depositor_public_key,
    );

    // kick-off 1
    let (kick_off_1_tx, kick_off_1_txid) = create_and_mine_kick_off_1_tx(
        &rpc,
        &operator_context,
        &kick_off_1_funding_utxo_address,
        kick_off_1_input_amount,
    ).await;

    // challenge
    let challenge_funding_outpoint = generate_stub_outpoint(
        &rpc,
        &challenge_funding_utxo_address,
        challenge_input_amount,
    );
    let challenge_crowdfunding_input = InputWithScript {
        outpoint: challenge_funding_outpoint,
        amount: challenge_input_amount,
        script: &generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
    };

    let vout = 0; // connector A
    let challenge_kick_off_input = Input {
        outpoint: OutPoint {
            txid: kick_off_1_txid,
            vout,
        },
        amount: kick_off_1_tx.output[vout as usize].value,
    };

    let mut challenge = ChallengeTransaction::new(
        &operator_context,
        challenge_kick_off_input,
        challenge_input_amount,
    );
    challenge.add_inputs_and_output(
        &depositor_context,
        &vec![challenge_crowdfunding_input],
        &depositor_context.depositor_keypair,
        generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
    ); // add crowdfunding input
    let challenge_tx = challenge.finalize();
    let challenge_txid = challenge_tx.compute_txid();

    // mine challenge tx
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &challenge_tx);
    helper::mint_block(&rpc, 1);
    helper::validate_tx(&rpc, challenge_txid);

    // operator balance check
    // TODO
}
