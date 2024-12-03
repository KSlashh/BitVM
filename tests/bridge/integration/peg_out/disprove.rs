use bitcoin::{Amount, OutPoint};
use bitvm::bridge::{
    connectors::connector::TaprootConnector, graphs::base::{HUGE_FEE_AMOUNT, INITIAL_AMOUNT}, scripts::generate_pay_to_pubkey_script_address, transactions::{
        assert::AssertTransaction,
        base::{BaseTransaction, Input},
        disprove::DisproveTransaction,
    },
    groth16::validate_assertions,
};
use bitvm::treepp::*;

use crate::bridge::{
    helper, integration::peg_out::utils::create_and_mine_kick_off_2_tx,
};

use crate::bridge::setup::{corrupt_assertions, get_wots_keys, setup_test, get_tapscripts, get_signed_assertions, get_groth16_proof};


#[tokio::test]
async fn test_disprove_success() {
    fn get_invalid_assertions() -> (usize, Script) {
        let (vk, _, _) = get_groth16_proof();
        let (wots_pk, _) = get_wots_keys();
        let mut signed_assertions = get_signed_assertions();
        let index = 1; // TODO: test all
        corrupt_assertions(&mut signed_assertions, index);
        let res = validate_assertions(&vk, signed_assertions, wots_pk);
        assert!(res.is_some(), "unexpected validate assertions result");
        res.unwrap()
    }

    let tap_scripts = get_tapscripts();
    let (
        rpc,
        _,
        operator_context,
        verifier_0_context,
        verifier_1_context,
        withdrawer_context,
        _,
        _,
        mut connector_c,
        _,
        _,
        connector_1,
        _,
        _,
        _,
        _,
        _,
        _,
    ) = setup_test(&tap_scripts).await;

    // verify funding inputs
    let kick_off_2_input_amount = Amount::from_sat(INITIAL_AMOUNT + 3*HUGE_FEE_AMOUNT);
    let kick_off_2_funding_utxo_address = connector_1.generate_taproot_address();

    connector_c.gen_taproot_address();

    // // generate invalid assertions
    use std::thread;
    const STACK_SIZE: usize = 32 * 1024 * 1024;
    let t = thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(get_invalid_assertions)
        .unwrap();
    let (leaf_index, hint_script) = t.join().unwrap();
    
    // let (vk, _, _) = get_groth16_proof();
    // let (wots_pk, _) = get_wots_keys();
    // let mut signed_assertions = get_signed_assertions();
    // let index = 10; // TODO: test wots256 & wots 160
    // corrupt_assertions(&mut signed_assertions, index);
    // let res = validate_assertions(&vk, signed_assertions, wots_pk);
    // assert!(res.is_some(), "unexpected validate assertions result");
    // let (leaf_index, hint_script) = res.unwrap();

    // kick-off 2
    let (kick_off_2_tx, kick_off_2_txid) = create_and_mine_kick_off_2_tx(
        &rpc,
        &operator_context,
        &kick_off_2_funding_utxo_address,
        kick_off_2_input_amount,
    )
    .await;

    // assert
    let vout = 1; // connector B
    let assert_input_0 = Input {
        outpoint: OutPoint {
            txid: kick_off_2_txid,
            vout,
        },
        amount: kick_off_2_tx.output[vout as usize].value,
    };
    let assert = AssertTransaction::new(&operator_context, assert_input_0, connector_c.clone());

    let assert_tx = assert.finalize();
    let assert_txid = assert_tx.compute_txid();
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &assert_tx);
    helper::mint_block(&rpc, 1);
    helper::validate_tx(&rpc, assert_txid);

    // disprove
    let vout = 1;
    let script_index = 1;
    let disprove_input_0 = Input {
        outpoint: OutPoint {
            txid: assert_txid,
            vout,
        },
        amount: assert_tx.output[vout as usize].value,
    };

    let vout = 2;
    let disprove_input_1 = Input {
        outpoint: OutPoint {
            txid: assert_txid,
            vout,
        },
        amount: assert_tx.output[vout as usize].value,
    };

    let mut disprove = DisproveTransaction::new(
        &operator_context,
        connector_c,
        disprove_input_0,
        disprove_input_1,
        script_index,
    );

    let secret_nonces_0 = disprove.push_nonces(&verifier_0_context);
    let secret_nonces_1 = disprove.push_nonces(&verifier_1_context);

    disprove.pre_sign(&verifier_0_context, &secret_nonces_0);
    disprove.pre_sign(&verifier_1_context, &secret_nonces_1);

    let reward_address = generate_pay_to_pubkey_script_address(
        withdrawer_context.network,
        &withdrawer_context.withdrawer_public_key,
    );
    let verifier_reward_script = reward_address.script_pubkey(); // send reward to withdrawer address

    // the following commitment should be obtained from the witness of the assert transaction
    disprove.add_input_output(leaf_index as u32, verifier_reward_script, hint_script);

    let disprove_tx = disprove.finalize();
    let disprove_txid = disprove_tx.compute_txid();

    // mine disprove
    helper::mint_block(&rpc, 1);
    helper::broadcast_tx(&rpc, &disprove_tx);
    helper::mint_block(&rpc, 1);
    helper::validate_tx(&rpc, disprove_txid);


    // reward balance check
    // TODO
}
