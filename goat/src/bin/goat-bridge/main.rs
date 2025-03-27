pub mod commands;
pub mod config;
pub mod files;
pub mod handles;

use core::str::FromStr;
use bitcoin::{OutPoint, Txid, Amount, Address};
use clap::{arg, command, Parser};
use commands::Commands;
use config::{load_config, match_network};
use goat_bridge::transactions::base::Input;
use handles::{
    handle_challenger_sign_disprove, handle_federation_presign, handle_generate_bitvm_instance, handle_generate_disprove_scripts, handle_generate_pegin_tx, handle_generate_prekickoff_tx, handle_generate_wots_keys, handle_operator_presign, handle_operator_sign_assert, handle_operator_sign_kickoff, handle_operator_sign_take1, handle_operator_sign_take2, handle_sign_proof, handle_verify_proof
};

#[derive(Parser)]
#[command(about = "goat bitvm cli-tools", long_about = None)]
struct Cli {
    /// config file path
    #[arg(short = 'c', long = "conf")]
    config_file: String,

    #[command(subcommand)]
    command: Commands,
}


#[derive(Debug)]
struct TxInputValue(Txid, u32, u64);

impl FromStr for TxInputValue {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            return Err(format!("invalid format: `{s}`,should be `string:u32:u64`"));
        }

        let txid = parts[0].parse::<Txid>().map_err(|e| format!("fail to parse input.txid: `{}`: {:?}", parts[0], e))?;
        let vout = parts[1].parse::<u32>().map_err(|e| format!("fail to parse input.vout: `{}`: {:?}", parts[1], e))?;
        let amount = parts[2].parse::<u64>().map_err(|e| format!("fail to parse input.amount: `{}`: {:?}", parts[2], e))?;

        Ok(TxInputValue(txid, vout, amount))
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::GenerateDisproveScripts{} => { 
            let conf = load_config(&cli.config_file);
            handle_generate_disprove_scripts(conf);
        },
        Commands::GenerateWotsKeys {secret_seed} => {
            let conf = load_config(&cli.config_file);
            handle_generate_wots_keys(conf, secret_seed);
        },
        Commands::SignProof {skip_validation} => {
            let conf = load_config(&cli.config_file);
            handle_sign_proof(conf, *skip_validation);
        },
        Commands::VerifyProof{} => {
            let conf = load_config(&cli.config_file);
            handle_verify_proof(conf);
        },
        Commands::GeneratePeginTx { tx_inputs, deposit_amount, fee_amount, change_address } => {
            let conf = load_config(&cli.config_file);
            let network = match_network(&conf.general.network).unwrap();
            let inputs = tx_inputs.iter()
                .map(|input| {
                    let txin = TxInputValue::from_str(input).expect("fail to parse tx inputs");
                    Input {
                        outpoint: OutPoint { 
                            txid: txin.0, 
                            vout: txin.1
                        },
                        amount: Amount::from_sat(txin.2),
                    }
                }).collect();
            let deposit_amount = Amount::from_sat(*deposit_amount);
            let fee_amount = Amount::from_sat(*fee_amount);
            let change_address = Address::from_str(change_address).expect("fail to parse change address")
                .require_network(network).expect("address failed the network check");
            handle_generate_pegin_tx(conf, inputs, deposit_amount, fee_amount, change_address);
        },
        Commands::GeneratePrekickoffTx { tx_inputs, stake_amount, fee_amount, change_address } => {
            let conf = load_config(&cli.config_file);
            let network = match_network(&conf.general.network).unwrap();
            let inputs = tx_inputs.iter()
                .map(|input| {
                    let txin = TxInputValue::from_str(input).expect("fail to parse tx inputs");
                    Input {
                        outpoint: OutPoint { 
                            txid: txin.0, 
                            vout: txin.1
                        },
                        amount: Amount::from_sat(txin.2),
                    }
                }).collect();
            let stake_amount = Amount::from_sat(*stake_amount);
            let fee_amount = Amount::from_sat(*fee_amount);
            let change_address = Address::from_str(change_address).expect("fail to parse change address")
                .require_network(network).expect("address fail to pass network check");
            handle_generate_prekickoff_tx(conf, inputs, stake_amount, fee_amount, change_address);
        },
        Commands::GenerateBitvmInstanace {} => {
            let conf = load_config(&cli.config_file);
            handle_generate_bitvm_instance(conf);
        },
        Commands::FederationPresign { } => {
            let conf = load_config(&cli.config_file);
            handle_federation_presign(conf);
        },
        Commands::OperatorPresign { } => {
            let conf = load_config(&cli.config_file);
            handle_operator_presign(conf);
        },
        Commands::OperatorSign { kickoff, evm_withdraw_txid, take_1, assert, take_2 } => {
            let conf = load_config(&cli.config_file);
            if *kickoff {
                let evm_withdraw_txid = evm_withdraw_txid.clone().expect("please provide --evm-withdraw-txid when signing kickoff tx");
                let evm_withdraw_txid = hex::decode(evm_withdraw_txid.trim_start_matches("0x")).expect("fail to decode evm_txid");
                let evm_withdraw_txid: [u8; 32] = evm_withdraw_txid.try_into().expect("invalid evm txid length");
                handle_operator_sign_kickoff(conf.clone(), evm_withdraw_txid);
            }
            if *take_1 {
                handle_operator_sign_take1(conf.clone());
            }
            if *assert {
                handle_operator_sign_assert(conf.clone());
            }
            if *take_2 {
                handle_operator_sign_take2(conf);
            }
        },
        Commands::Disprove { reward_address } => {
            let conf = load_config(&cli.config_file);
            let network = match_network(&conf.general.network).unwrap();
            let reward_address = Address::from_str(reward_address).expect("fail to parse reward address")
                .require_network(network).expect("address fail to pass network check");
            handle_challenger_sign_disprove(conf, reward_address);
        }
    }
}

#[test]
fn generate_test_keys() {
    use goat_bridge::contexts::{
        base::generate_keys_from_secret,
        depositor::DepositorContext,
        operator::OperatorContext,
        verifier::VerifierContext,
    };
    use bitcoin::{PublicKey, Network};

    let source_network = Network::Regtest;
    const OPERATOR_SECRET: &str = "3076ca1dfc1e383be26d5dd3c0c427340f96139fa8c2520862cf551ec2d670ac";
    const VERIFIER_0_SECRET: &str = "ee0817eac0c13aa8ee2dd3256304041f09f0499d1089b56495310ae8093583e2";
    const VERIFIER_1_SECRET: &str = "fc294c70faf210d4d0807ea7a3dba8f7e41700d90c119e1ae82a0687d89d297f";
    const DEPOSITOR_SECRET: &str = "b8f17ea979be24199e7c3fec71ee88914d92fd4ca508443f765d56ce024ef1d7";

    let (_, verifier_0_public_key) = generate_keys_from_secret(source_network, VERIFIER_0_SECRET);
    let (_, verifier_1_public_key) = generate_keys_from_secret(source_network, VERIFIER_1_SECRET);
    let mut n_of_n_public_keys: Vec<PublicKey> = Vec::new();
    n_of_n_public_keys.push(verifier_0_public_key);
    n_of_n_public_keys.push(verifier_1_public_key);

    let depositor_context =
        DepositorContext::new(source_network, DEPOSITOR_SECRET, &n_of_n_public_keys);
    let operator_context =
        OperatorContext::new(source_network, OPERATOR_SECRET, &n_of_n_public_keys);
    let verifier_0_context =
        VerifierContext::new(source_network, VERIFIER_0_SECRET, &n_of_n_public_keys);
    // let verifier_1_context =
    //     VerifierContext::new(source_network, VERIFIER_1_SECRET, &n_of_n_public_keys);

    dbg!(depositor_context.depositor_taproot_public_key.to_string());
    dbg!(depositor_context.depositor_public_key.to_string());
    dbg!(DEPOSITOR_SECRET);
    dbg!("");
    dbg!(operator_context.operator_taproot_public_key.to_string());
    dbg!(operator_context.operator_public_key.to_string());
    dbg!(OPERATOR_SECRET);
    dbg!("");
    dbg!(verifier_0_context.n_of_n_taproot_public_key.to_string());
    dbg!(verifier_0_context.n_of_n_public_key.to_string());
    dbg!(verifier_0_context.n_of_n_public_keys[0].to_string());
    dbg!(verifier_0_context.n_of_n_public_keys[1].to_string());
    dbg!(VERIFIER_0_SECRET);
    dbg!(VERIFIER_1_SECRET);
    // dbg!("");
    // dbg!(verifier_1_context.n_of_n_taproot_public_key.to_string());
    // dbg!(verifier_1_context.n_of_n_public_key.to_string());
    // dbg!(verifier_1_context.n_of_n_public_keys[0].to_string());
    // dbg!(verifier_1_context.n_of_n_public_keys[1].to_string());
    // dbg!(VERIFIER_1_SECRET);

}

#[test]
#[ignore]
fn generate_corrupt_proof() {
    let conf_file = "./src/bin/goat-bridge/example.config.toml";
    let conf = load_config(&conf_file);
    // let target_script_index: u32 = 8;
    let target_bitcom_index: usize = 8;

    println!("loading operator wots secret keys ...");
    assert!(files::file_exists(&conf.operator.operator_wots_seckey_file), "operator_wots_seckey_file not provided");
    let wots_sec = files::load_wots_seckeys(&conf.operator.operator_wots_seckey_file);

    println!("loading proof signatures ...");
    assert!(files::file_exists(&conf.general.proof_file), "proof-sigs not provided");
    let mut proof_sigs = files::load_signed_assertions_from_file(&conf.general.signed_assertions_file);
    
    handles::corrupt(&mut proof_sigs, &wots_sec.1, target_bitcom_index);

    println!("loading vkey ...");
    assert!(files::file_exists(&conf.general.vkey_file), "vkey not provided");
    let ark_vkey = files::load_groth16_vk(&conf.general.vkey_file);
    
    println!("loading operator wots public-key...");
    assert!(files::file_exists(&conf.general.operator_wots_pubkey_file), "operator wots public key is not provided");
    let pubkey = files::load_wots_pubkeys(&conf.general.operator_wots_pubkey_file);

    println!("loading disprove scripts...");
    assert!(files::file_exists(&conf.general.disprove_scripts_file), "disprove scripts is not provided");
    let disprove_scripts = files::load_scripts_from_file(&conf.general.disprove_scripts_file).try_into().unwrap();

    let res = bitvm::chunk::api::validate_assertions(&ark_vkey, proof_sigs, pubkey.1, &disprove_scripts);
    match res {
        Some((index,witness)) => {
            files::write_disprove_witness(&conf.challenger.disprove_witness_file, index, witness);
            println!("\nProof is invalid! Disprove witness is written to: {}", &conf.challenger.disprove_witness_file);
        },
        _ => {
            println!("\nProof is Ok.");
        }
    };
    
}   

#[test]
#[ignore]
fn test_disprove_scripts_size() {
    let conf_file = "./src/bin/goat-bridge/example.config.toml";
    let conf = load_config(&conf_file);
    
    assert!(files::file_exists(&conf.general.disprove_scripts_file), "disprove scripts not provided");
    let disprove_scripts_bytes = files::load_scripts_bytes_from_file(&conf.general.disprove_scripts_file);

    let scr_num = disprove_scripts_bytes.len();
    let mut sum_bytes = 0;
    let mut min_scr = (0, 10000000000);
    for i in 0..disprove_scripts_bytes.len() {
        let scr_len = disprove_scripts_bytes[i].len();
        min_scr = if min_scr.1 > scr_len {
            (i, scr_len)
        } else {
            min_scr
        };
        sum_bytes += scr_len;
        println!("script {i} size: {scr_len}");
    }
    println!("total {scr_num} scripts");
    println!("total {sum_bytes} bytes");
    println!("min script: {:?} , size: {:?}", min_scr.0, min_scr.1);
}   

