use bitcoin::{Amount, OutPoint};
use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::{DUST_AMOUNT, FEE_AMOUNT, HUGE_FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        disprove_chain::DisproveChainTransaction,
    },
};

use crate::bridge::{
    helper, integration::peg_out::utils::create_and_mine_kick_off_2_tx,
    setup::{setup_test, get_bitcom_lock_scripts},
};

#[tokio::test]
async fn test_disprove_chain_success() {
    let empty_script = vec![];
    let bitcom_lock_script = get_bitcom_lock_scripts();
    let (
        rpc,
        _,
        operator_context,
        verifier_0_context,
        verifier_1_context,
        withdrawer_context,
        _,
        _,
        _,
        _,
        _,
        connector_1,
        _,
        _,
        _,
        _,
        revealers,
        _,
        _,
    ) = setup_test(&empty_script, &bitcom_lock_script).await;

    // verify funding inputs
    let kick_off_2_input_amount = Amount::from_sat(INITIAL_AMOUNT + HUGE_FEE_AMOUNT + FEE_AMOUNT + DUST_AMOUNT);
    let kick_off_2_funding_utxo_address = connector_1.generate_taproot_address();

    // kick-off 2
    let (kick_off_2_tx, kick_off_2_txid) = create_and_mine_kick_off_2_tx(
        &rpc,
        &operator_context,
        &kick_off_2_funding_utxo_address,
        kick_off_2_input_amount,
        revealers,
    )
    .await;

    // disprove chain
    let vout = 1; // connector B
    let disprove_chain_input_0 = Input {
        outpoint: OutPoint {
            txid: kick_off_2_txid,
            vout,
        },
        amount: kick_off_2_tx.output[vout as usize].value,
    };

    let mut disprove_chain =
        DisproveChainTransaction::new(&operator_context, disprove_chain_input_0);

    let secret_nonces_0 = disprove_chain.push_nonces(&verifier_0_context);
    let secret_nonces_1 = disprove_chain.push_nonces(&verifier_1_context);

    disprove_chain.pre_sign(&verifier_0_context, &secret_nonces_0);
    disprove_chain.pre_sign(&verifier_1_context, &secret_nonces_1);

    let reward_address = generate_pay_to_pubkey_script_address(
        withdrawer_context.network,
        &withdrawer_context.withdrawer_public_key,
    );
    disprove_chain.add_output(reward_address.script_pubkey());

    let disprove_chain_tx = disprove_chain.finalize();
    let disprove_chain_txid = disprove_chain_tx.compute_txid();

    // mine disprove chain
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &disprove_chain_tx);
    helper::mint_block(&rpc, 1);
    helper::validate_tx(&rpc, disprove_chain_txid);

    // reward balance check
    // TODO
}
