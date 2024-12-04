#[cfg(test)]
#[allow(unused_variables)]
mod tests {
    use bitcoin::{Amount, ScriptBuf};
    use bitvm::treepp::*;

    use bitvm::bridge::{
        connectors::connector::TaprootConnector, graphs::base::{DUST_AMOUNT, HUGE_FEE_AMOUNT, INITIAL_AMOUNT}, 
        scripts::generate_pay_to_pubkey_script_address, transactions::{
            base::{BaseTransaction, Input},
            disprove::DisproveTransaction,
        },
        groth16::{validate_assertions, recover_corrupt_assertions, corrupt_signed_assertions},
    };
    use bitvm::groth16::g16;
    use crate::bridge::setup::{corrupt_assertions, get_wots_keys, setup_test, get_tapscripts, get_signed_assertions, get_groth16_proof};
    use crate::bridge::helper::{self, generate_stub_outpoint};
    use std::fs::OpenOptions;
    use std::io::{Write, BufReader, BufRead};
    use regex::Regex;

    #[tokio::test]
    async fn test_should_be_able_to_submit_disprove_tx_successfully() {
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
            _,
            _,
            _,
            _,
            connector_5,
            _,
            _,
        ) = setup_test(&tap_scripts).await;

        connector_c.gen_taproot_address();
        let amount_0 = Amount::from_sat(DUST_AMOUNT);
        let amount_1 = Amount::from_sat(INITIAL_AMOUNT + HUGE_FEE_AMOUNT);
        let connector_5_addr = connector_5.generate_taproot_address();
        let connector_c_addr = connector_c.generate_taproot_address();
        let outpoint_0 =
            generate_stub_outpoint(&rpc, &connector_5_addr, amount_0);
        let outpoint_1 =
            generate_stub_outpoint(&rpc, &connector_c_addr, amount_1);

        // generate invalid assertions
        use std::thread;
        const STACK_SIZE: usize = 32 * 1024 * 1024;
        let t = thread::Builder::new()
            .stack_size(STACK_SIZE)
            .spawn(get_invalid_assertions)
            .unwrap();
        let (leaf_index, hint_script) =  match t.join() {
            Ok(v) => v, 
            Err(e) => panic!("error get_invalid_assertions: {e:?}"),
        };

        let mut disprove_tx = DisproveTransaction::new(
            &operator_context,
            connector_c,
            Input {
                outpoint: outpoint_0,
                amount: amount_0,
            },
            Input {
                outpoint: outpoint_1,
                amount: amount_1,
            },
            leaf_index as u32,
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

        disprove_tx.add_input_output(leaf_index as u32, verifier_reward_script, hint_script);

        let tx = disprove_tx.finalize();
        // println!("Script Path Spend Transaction: {:?}\n", tx);
        println!("connector_c_witness_size: {:?}", tx.input[1].witness.size());
        println!("total_size: {:?}", tx.total_size());
        println!("weight: {:?}", tx.weight());
        helper::mint_block(&rpc, 1);
        helper::broadcast_tx(&rpc, &tx);
        helper::mint_block(&rpc, 1);
        let txid = tx.compute_txid();
        println!("Txid: {:?}", txid.clone());
        helper::validate_tx(&rpc, txid);
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct DisproveInput {
        leaf_index: usize,
        hint_script: Vec<u8>,
    }

    fn read_disprove_input(index: usize) -> (usize, Script){
        let res_file_name = &format!("chunker_data/disprove/disprove_{index}.json");
        let file = OpenOptions::new().read(true).open(res_file_name).expect(&format!("fail to open chunker_data/disprove/disprove_{index}.json"));
        let reader = BufReader::new(file);
        let res: DisproveInput = serde_json::from_reader(reader).expect(&format!("fail to deserialize chunker_data/disprove/disprove_{index}.json"));
        let hint_script = script! {};
        let bf = ScriptBuf::from_bytes(res.hint_script);
        let hint_script = hint_script.push_script(bf);
        (res.leaf_index, hint_script)
    }

    #[test]
    fn test_generate_disprove_inputs() {
        fn run() {
            let (vk, _, _) = get_groth16_proof();
            let (wots_pk, wots_sk) = get_wots_keys();
            let mut signed_assertions = get_signed_assertions();

            for i in 0..(g16::N_VERIFIER_PUBLIC_INPUTS + g16::N_VERIFIER_FQS + g16::N_VERIFIER_HASHES) {
                let res_file_name = &format!("chunker_data/disprove/disprove_{i}.json");
                let mut file = match OpenOptions::new().write(true).create_new(true).open(res_file_name) {
                    Ok(f) => f,
                    Err(e) => {
                        continue;
                    },
                };

                let correct_sig = corrupt_signed_assertions(&wots_sk, &mut signed_assertions, i);
                let (leaf_index, hint_script) = validate_assertions(&vk, signed_assertions, wots_pk).unwrap();
                recover_corrupt_assertions(&mut signed_assertions, i, correct_sig);
                
                let hint_script = hint_script.compile().to_bytes();
                let json = serde_json::to_string(&DisproveInput{leaf_index, hint_script}).unwrap();
                file.write_all(json.as_bytes()).expect("fail to write disprove input to file");
            }
        }

        use std::thread;
        const STACK_SIZE: usize = 32 * 1024 * 1024;
        let t = thread::Builder::new()
            .stack_size(STACK_SIZE)
            .spawn(run)
            .unwrap();
        t.join().unwrap();
    }
    
    #[tokio::test]
    async fn test_all_disprove_tapnode() {
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
            _,
            _,
            _,
            _,
            connector_5,
            _,
            _,
        ) = setup_test(&tap_scripts).await;
        connector_c.gen_taproot_address();

        let amount_0 = Amount::from_sat(DUST_AMOUNT);
        let amount_1 = Amount::from_sat(INITIAL_AMOUNT + HUGE_FEE_AMOUNT);
        let connector_5_addr = connector_5.generate_taproot_address();
        let connector_c_addr = connector_c.generate_taproot_address();
        let reward_address = generate_pay_to_pubkey_script_address(
            withdrawer_context.network,
            &withdrawer_context.withdrawer_public_key,
        );
        let verifier_reward_script = reward_address.script_pubkey(); // send reward to withdrawer address

        // continue previous test
        let res_file_name = "chunker_data/disprove_tx_test_res.txt";
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(res_file_name)
            .unwrap();
        let lines: Vec<String> = BufReader::new(f).lines().collect::<Result<_, _>>().unwrap();
        let start_index = if let Some(last_line) = lines.last() {
            let re = Regex::new(r"assertion_(\d+):").unwrap();
            if let Some(captures) = re.captures(last_line) {
                if let Some(i_match) = captures.get(1) {
                    if let Ok(i) = i_match.as_str().parse::<usize>() {
                        i + 1
                    } else { panic!() }
                } else { panic!() }
            } else { panic!() }
        } else { 0 };
                
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(res_file_name)
            .unwrap();
        for i in start_index..(g16::N_VERIFIER_PUBLIC_INPUTS + g16::N_VERIFIER_FQS + g16::N_VERIFIER_HASHES) {
            let (leaf_index, hint_script) = read_disprove_input(i);
            
            let outpoint_0 =
                generate_stub_outpoint(&rpc, &connector_5_addr, amount_0);
            let outpoint_1 =
                generate_stub_outpoint(&rpc, &connector_c_addr, amount_1);

            let mut disprove_tx = DisproveTransaction::new(
                &operator_context,
                connector_c.clone(),
                Input {
                    outpoint: outpoint_0,
                    amount: amount_0,
                },
                Input {
                    outpoint: outpoint_1,
                    amount: amount_1,
                },
                leaf_index as u32,
            );

            let secret_nonces_0 = disprove_tx.push_nonces(&verifier_0_context);
            let secret_nonces_1 = disprove_tx.push_nonces(&verifier_1_context);

            disprove_tx.pre_sign(&verifier_0_context, &secret_nonces_0);
            disprove_tx.pre_sign(&verifier_1_context, &secret_nonces_1);

            disprove_tx.add_input_output(leaf_index as u32, verifier_reward_script.clone(), hint_script);

            let tx = disprove_tx.finalize();
            helper::mint_block(&rpc, 1);
            helper::broadcast_tx(&rpc, &tx);
            helper::mint_block(&rpc, 1);
            let txid = tx.compute_txid();
            helper::validate_tx(&rpc, txid);

            let test_res = &format!("\nassertion_{i}: tx-weight: {:?}, txid: {:?}", tx.weight(), txid);
            file.write_all(&test_res.as_bytes()).unwrap();
        } 
    }
}
