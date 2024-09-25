#[cfg(test)]
mod tests {

    use aws_sdk_s3::config::http::HttpResponse;
    use bitcoin::{
        consensus::encode::serialize_hex, key::Keypair, Amount, Network, PrivateKey, PublicKey,
        TxOut,
    };

    use bitvm::bridge::{
        connectors::{connector::TaprootConnector, connector_5}, contexts::withdrawer, graphs::base::{DUST_AMOUNT, FEE_AMOUNT, HUGE_FEE_AMOUNT, INITIAL_AMOUNT}, hash_chain, scripts::{generate_pay_to_pubkey_script, generate_pay_to_pubkey_script_address}, transactions::{
            base::{BaseTransaction, Input},
            disprove::DisproveTransaction,
        }
    };
    use serde::de::Expected;

    use crate::bridge::assert;

    use super::super::super::{helper::generate_stub_outpoint, setup::setup_test};

    use esplora_client::Error;

    #[tokio::test]
    async fn test_should_be_able_to_submit_disprove_tx_successfully() {
        let (
            client,
            _,
            _,
            operator_context,
            verifier_0_context,
            verifier_1_context,
            withdrawer_context,
            _,
            _,
            connector_c,
            _,
            _,
            _,
            _,
            _,
            _,
            connector_5,
            _,
            _,
            statement,
        ) = setup_test().await;

        let amount_0 = Amount::from_sat(DUST_AMOUNT);
        let outpoint_0 =
            generate_stub_outpoint(&client, &connector_5.generate_taproot_address(), amount_0)
                .await;

        let amount_1 = Amount::from_sat(INITIAL_AMOUNT + HUGE_FEE_AMOUNT);
        let outpoint_1 =
            generate_stub_outpoint(&client, &connector_c.generate_taproot_address(), amount_1)
                .await;

        let script_index = 1;
        let mut disprove_tx = DisproveTransaction::new(
            &operator_context,
            Input {
                outpoint: outpoint_0,
                amount: amount_0,
            },
            Input {
                outpoint: outpoint_1,
                amount: amount_1,
            },
            script_index,
        );

        let secret_nonces_0 = disprove_tx.push_nonces(&verifier_0_context);
        let secret_nonces_1 = disprove_tx.push_nonces(&verifier_1_context);

        disprove_tx.pre_sign(&verifier_0_context, &secret_nonces_0);
        disprove_tx.pre_sign(&verifier_1_context, &secret_nonces_1);

        let reward_address = generate_pay_to_pubkey_script_address(
            withdrawer_context.network,
            &withdrawer_context.withdrawer_public_key,
        );
        let verifier_reward_script = reward_address.script_pubkey(); // send reward to withdrawer address

        // the following commitment should be obtained from the witness of the assert transaction
        let invalid_statement = [0u8; 20];
        let pre_commitment = hash_chain::gen_commitment_unlock_witness(&operator_context.operator_commitment_seckey, &statement, script_index);
        let post_commitment = hash_chain::gen_commitment_unlock_witness(&operator_context.operator_commitment_seckey, &invalid_statement, script_index+1);        

        disprove_tx.add_input_output(script_index, verifier_reward_script, &pre_commitment, &post_commitment);

        let tx = disprove_tx.finalize();
        // println!("Script Path Spend Transaction: {:?}\n", tx);
        let result = client.esplora.broadcast(&tx).await;
        println!("\nTxid: {:?}", tx.compute_txid());
        println!("Broadcast result: {:?}\n", result);
        // println!("Transaction hex: \n{}", serialize_hex(&tx));
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_disprove_should_revert_with_valid_commitment()
    {
        let (
            client,
            _,
            _,
            operator_context,
            verifier_0_context,
            verifier_1_context,
            withdrawer_context,
            _,
            _,
            connector_c,
            _,
            _,
            _,
            _,
            _,
            _,
            connector_5,
            _,
            _,
            statement,
        ) = setup_test().await;

        let amount_0 = Amount::from_sat(DUST_AMOUNT);
        let outpoint_0 =
            generate_stub_outpoint(&client, &connector_5.generate_taproot_address(), amount_0)
                .await;

        let amount_1 = Amount::from_sat(INITIAL_AMOUNT);
        let outpoint_1 =
            generate_stub_outpoint(&client, &connector_c.generate_taproot_address(), amount_1)
                .await;

        let script_index = 1;
        let mut disprove_tx = DisproveTransaction::new(
            &operator_context,
            Input {
                outpoint: outpoint_0,
                amount: amount_0,
            },
            Input {
                outpoint: outpoint_1,
                amount: amount_1,
            },
            1,
        );

        let secret_nonces_0 = disprove_tx.push_nonces(&verifier_0_context);
        let secret_nonces_1 = disprove_tx.push_nonces(&verifier_1_context);

        disprove_tx.pre_sign(&verifier_0_context, &secret_nonces_0);
        disprove_tx.pre_sign(&verifier_1_context, &secret_nonces_1);

        let reward_address = generate_pay_to_pubkey_script_address(
            withdrawer_context.network,
            &withdrawer_context.withdrawer_public_key,
        );
        let verifier_reward_script = reward_address.script_pubkey(); // send reward to withdrawer address

        // the following commitment should be obtained from the witness of the assert transaction
        let pre_commitment = hash_chain::gen_commitment_unlock_witness(&operator_context.operator_commitment_seckey, &statement, script_index);
        let post_commitment = hash_chain::gen_commitment_unlock_witness(&operator_context.operator_commitment_seckey, &statement, script_index+1);        

        disprove_tx.add_input_output(script_index, verifier_reward_script, &pre_commitment, &post_commitment);

        let tx = disprove_tx.finalize();
        // println!("Script Path Spend Transaction: {:?}\n", tx);
        let result = client.esplora.broadcast(&tx).await;
        println!("\nTxid: {:?}", tx.compute_txid());
        println!("Broadcast result: {:?}\n", result);
        // println!("Transaction hex: \n{}", serialize_hex(&tx));
        let expect_err = Error::HttpResponse{
            status: 400,
            message: "sendrawtransaction RPC error: {\"code\":-26,\"message\":\"mandatory-script-verify-flag-failed (OP_RETURN was encountered)\"}".to_string(),
        };
        dbg!(expect_err);
        assert!(result.is_err());
    }
}
