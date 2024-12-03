#[cfg(test)]
mod tests {

    use bitcoin::{
        key::Keypair, Amount, PrivateKey, PublicKey,
    };

    use bitvm::bridge::{
        connectors::connector::TaprootConnector,
        graphs::base::INITIAL_AMOUNT,
        scripts::generate_pay_to_pubkey_script,
        transactions::{
            base::{BaseTransaction, Input},
            disprove_chain::DisproveChainTransaction,
        },
    };

    use super::super::super::{helper::{generate_stub_outpoint, self}, setup::setup_test};

    #[tokio::test]
    async fn test_should_be_able_to_submit_disprove_chain_tx_successfully() {
        let empty_script = vec![];
        let (
            rpc,
            _,
            operator_context,
            verifier_0_context,
            verifier_1_context,
            _,
            _,
            connector_b,
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

        let amount = Amount::from_sat(INITIAL_AMOUNT);
        let outpoint =
            generate_stub_outpoint(&rpc, &connector_b.generate_taproot_address(), amount);

        let mut disprove_chain_tx =
            DisproveChainTransaction::new(&operator_context, Input { outpoint, amount });

        let secret_nonces_0 = disprove_chain_tx.push_nonces(&verifier_0_context);
        let secret_nonces_1 = disprove_chain_tx.push_nonces(&verifier_1_context);

        disprove_chain_tx.pre_sign(&verifier_0_context, &secret_nonces_0);
        disprove_chain_tx.pre_sign(&verifier_1_context, &secret_nonces_1);

        let tx = disprove_chain_tx.finalize();
        helper::mint_block(&rpc, 1);
        helper::broadcast_tx(&rpc, &tx);
        helper::mint_block(&rpc, 1);
        let txid = tx.compute_txid();
        println!("Txid: {:?}", txid.clone());
        helper::validate_tx(&rpc, txid);
    }

    #[tokio::test]
    async fn test_should_be_able_to_submit_disprove_chain_tx_with_verifier_added_to_output_successfully(
    ) {
        let empty_script = vec![];
        let (
            rpc,
            _,
            operator_context,
            verifier_0_context,
            verifier_1_context,
            _,
            _,
            connector_b,
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

        let amount = Amount::from_sat(INITIAL_AMOUNT);
        let outpoint =
            generate_stub_outpoint(&rpc, &connector_b.generate_taproot_address(), amount);

        let mut disprove_chain_tx =
            DisproveChainTransaction::new(&operator_context, Input { outpoint, amount });

        let secret_nonces_0 = disprove_chain_tx.push_nonces(&verifier_0_context);
        let secret_nonces_1 = disprove_chain_tx.push_nonces(&verifier_1_context);

        disprove_chain_tx.pre_sign(&verifier_0_context, &secret_nonces_0);
        disprove_chain_tx.pre_sign(&verifier_1_context, &secret_nonces_1);


        let secp = verifier_0_context.secp;
        let verifier_secret: &str =
            "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffff1234";
        let verifier_keypair = Keypair::from_seckey_str(&secp, verifier_secret).unwrap();
        let verifier_private_key =
            PrivateKey::new(verifier_keypair.secret_key(), verifier_0_context.network);
        let verifier_pubkey = PublicKey::from_private_key(&secp, &verifier_private_key); 
        disprove_chain_tx.add_output(generate_pay_to_pubkey_script(&verifier_pubkey));

        let tx = disprove_chain_tx.finalize();
        helper::mint_block(&rpc, 1);
        helper::broadcast_tx(&rpc, &tx);
        helper::mint_block(&rpc, 1);
        let txid = tx.compute_txid();
        println!("Txid: {:?}", txid.clone());
        helper::validate_tx(&rpc, txid);
    }
}
