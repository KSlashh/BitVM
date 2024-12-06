use bitcoin::{Network, PublicKey};
use bitvm::{bridge::{
    client::client::BitVMClient, constants::DestinationNetwork,
    connectors::{
        connector_0::Connector0, connector_1::Connector1, connector_2::Connector2,
        connector_3::Connector3, connector_4::Connector4, connector_5::Connector5,
        connector_a::ConnectorA, connector_b::ConnectorB, connector_c::ConnectorC,
        connector_z::ConnectorZ,
    }, contexts::{
        base::generate_keys_from_secret, depositor::DepositorContext, operator::OperatorContext,
        verifier::VerifierContext, withdrawer::WithdrawerContext,
    }, graphs::base::{
        DEPOSITOR_EVM_ADDRESS, DEPOSITOR_SECRET, OPERATOR_SECRET, VERIFIER_0_SECRET, VERIFIER_1_SECRET, WITHDRAWER_EVM_ADDRESS, WITHDRAWER_SECRET
    }
}, groth16::g16, treepp::*};
use bitvm::bridge::groth16::{
    Proof, WotsSignatures, VerifyingKey, PublicInputs, TEST_SECRET, WotsPublicKeys, WotsSecretKeys,
    load_all_signed_assertions_from_file, load_assert_tapscripts_from_file, load_proof_from_file, 
    corrupt_signed_assertions, generate_wots_keys_from_secrets,
};
use bitcoincore_rpc::Client;

use super::helper;

pub async fn testnet_setup<'a>(tap_scripts: &'a Vec<Script>) -> (
    BitVMClient<'a>,
    BitVMClient<'a>,
    DepositorContext,
    OperatorContext,
    VerifierContext,
    VerifierContext,
    WithdrawerContext,
    ConnectorA,
    ConnectorB,
    ConnectorC<'a>,
    ConnectorZ,
    Connector0,
    Connector1,
    Connector2,
    Connector3,
    Connector4,
    Connector5,
    String,
    String,
) {
    let source_network = Network::Testnet;
    let destination_network = DestinationNetwork::EthereumSepolia;

    let (_, _, verifier_0_public_key) =
        generate_keys_from_secret(source_network, VERIFIER_0_SECRET);
    let (_, _, verifier_1_public_key) =
        generate_keys_from_secret(source_network, VERIFIER_1_SECRET);
    let mut n_of_n_public_keys: Vec<PublicKey> = Vec::new();
    n_of_n_public_keys.push(verifier_0_public_key);
    n_of_n_public_keys.push(verifier_1_public_key);

    let depositor_context =
        DepositorContext::new(source_network, DEPOSITOR_SECRET, &n_of_n_public_keys);
    let operator_context =
        OperatorContext::new(source_network, OPERATOR_SECRET, &n_of_n_public_keys);
    let verifier_0_context =
        VerifierContext::new(source_network, VERIFIER_0_SECRET, &n_of_n_public_keys);
    let verifier_1_context =
        VerifierContext::new(source_network, VERIFIER_1_SECRET, &n_of_n_public_keys);
    let withdrawer_context =
        WithdrawerContext::new(source_network, WITHDRAWER_SECRET, &n_of_n_public_keys);

    let client_0 = BitVMClient::new(
        source_network,
        destination_network,
        &n_of_n_public_keys,
        Some(DEPOSITOR_SECRET),
        Some(OPERATOR_SECRET),
        Some(VERIFIER_0_SECRET),
        Some(WITHDRAWER_SECRET),
    )
    .await;

    let client_1 = BitVMClient::new(
        source_network,
        destination_network,
        &n_of_n_public_keys,
        Some(DEPOSITOR_SECRET),
        Some(OPERATOR_SECRET),
        Some(VERIFIER_1_SECRET),
        Some(WITHDRAWER_SECRET),
    )
    .await;

    let connector_a = ConnectorA::new(
        source_network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_b = ConnectorB::new(source_network, &operator_context.n_of_n_taproot_public_key);
    let connector_z = ConnectorZ::new(
        source_network,
        DEPOSITOR_EVM_ADDRESS,
        &depositor_context.depositor_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_0 = Connector0::new(source_network, &operator_context.n_of_n_taproot_public_key);
    let connector_1 = Connector1::new(
        source_network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_2 = Connector2::new(
        source_network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_3 = Connector3::new(source_network, &operator_context.operator_public_key);
    let connector_4 = Connector4::new(source_network, &operator_context.operator_public_key);
    let connector_5 = Connector5::new(source_network, &operator_context.n_of_n_taproot_public_key);

    let connector_c = ConnectorC::new(source_network, &operator_context.operator_taproot_public_key, &tap_scripts);

    return (
        client_0,
        client_1,
        depositor_context,
        operator_context,
        verifier_0_context,
        verifier_1_context,
        withdrawer_context,
        connector_a,
        connector_b,
        connector_c,
        connector_z,
        connector_0,
        connector_1,
        connector_2,
        connector_3,
        connector_4,
        connector_5,
        DEPOSITOR_EVM_ADDRESS.to_string(),
        WITHDRAWER_EVM_ADDRESS.to_string(),
    );
}

pub async fn new_client<'a>() -> (
    BitVMClient<'a>,
    BitVMClient<'a>,
) {
    let source_network = Network::Regtest;
    let destination_network = DestinationNetwork::EthereumSepolia;
    let (_, _, verifier_0_public_key) =
        generate_keys_from_secret(source_network, VERIFIER_0_SECRET);
    let (_, _, verifier_1_public_key) =
        generate_keys_from_secret(source_network, VERIFIER_1_SECRET);
    let mut n_of_n_public_keys: Vec<PublicKey> = Vec::new();
    n_of_n_public_keys.push(verifier_0_public_key);
    n_of_n_public_keys.push(verifier_1_public_key);
    (
        BitVMClient::new(
            source_network,
            destination_network,
            &n_of_n_public_keys,
            Some(DEPOSITOR_SECRET),
            Some(OPERATOR_SECRET),
            Some(VERIFIER_0_SECRET),
            Some(WITHDRAWER_SECRET),
        ).await,
        BitVMClient::new(
            source_network,
            destination_network,
            &n_of_n_public_keys,
            Some(DEPOSITOR_SECRET),
            Some(OPERATOR_SECRET),
            Some(VERIFIER_1_SECRET),
            Some(WITHDRAWER_SECRET),
        ).await,
    )
}

pub async fn setup_test<'a>(tap_scripts: &'a Vec<Script>) -> (
    // BitVMClient<'a>,
    // BitVMClient<'a>,
    Client,
    DepositorContext,
    OperatorContext,
    VerifierContext,
    VerifierContext,
    WithdrawerContext,
    ConnectorA,
    ConnectorB,
    ConnectorC<'a>,
    ConnectorZ,
    Connector0,
    Connector1,
    Connector2,
    Connector3,
    Connector4,
    Connector5,
    String,
    String,
) {
    let source_network = Network::Regtest;
    // let destination_network = DestinationNetwork::EthereumSepolia;

    let (_, _, verifier_0_public_key) =
        generate_keys_from_secret(source_network, VERIFIER_0_SECRET);
    let (_, _, verifier_1_public_key) =
        generate_keys_from_secret(source_network, VERIFIER_1_SECRET);
    let mut n_of_n_public_keys: Vec<PublicKey> = Vec::new();
    n_of_n_public_keys.push(verifier_0_public_key);
    n_of_n_public_keys.push(verifier_1_public_key);

    let depositor_context =
        DepositorContext::new(source_network, DEPOSITOR_SECRET, &n_of_n_public_keys);
    let operator_context =
        OperatorContext::new(source_network, OPERATOR_SECRET, &n_of_n_public_keys);
    let verifier_0_context =
        VerifierContext::new(source_network, VERIFIER_0_SECRET, &n_of_n_public_keys);
    let verifier_1_context =
        VerifierContext::new(source_network, VERIFIER_1_SECRET, &n_of_n_public_keys);
    let withdrawer_context =
        WithdrawerContext::new(source_network, WITHDRAWER_SECRET, &n_of_n_public_keys);

    let rpc = helper::new_rpc_client().await;
    // let client_0 = BitVMClient::new(
    //     source_network,
    //     destination_network,
    //     &n_of_n_public_keys,
    //     Some(DEPOSITOR_SECRET),
    //     Some(OPERATOR_SECRET),
    //     Some(VERIFIER_0_SECRET),
    //     Some(WITHDRAWER_SECRET),
    // )
    // .await;

    // let client_1 = BitVMClient::new(
    //     source_network,
    //     destination_network,
    //     &n_of_n_public_keys,
    //     Some(DEPOSITOR_SECRET),
    //     Some(OPERATOR_SECRET),
    //     Some(VERIFIER_1_SECRET),
    //     Some(WITHDRAWER_SECRET),
    // )
    // .await;

    let connector_a = ConnectorA::new(
        source_network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_b = ConnectorB::new(source_network, &operator_context.n_of_n_taproot_public_key);
    let connector_z = ConnectorZ::new(
        source_network,
        DEPOSITOR_EVM_ADDRESS,
        &depositor_context.depositor_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_0 = Connector0::new(source_network, &operator_context.n_of_n_taproot_public_key);
    let connector_1 = Connector1::new(
        source_network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_2 = Connector2::new(
        source_network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_3 = Connector3::new(source_network, &operator_context.operator_public_key);
    let connector_4 = Connector4::new(source_network, &operator_context.operator_public_key);
    let connector_5 = Connector5::new(source_network, &operator_context.n_of_n_taproot_public_key);

    let connector_c = ConnectorC::new(source_network, &operator_context.operator_taproot_public_key, &tap_scripts);

    return (
        // client_0,
        // client_1,
        rpc,
        depositor_context,
        operator_context,
        verifier_0_context,
        verifier_1_context,
        withdrawer_context,
        connector_a,
        connector_b,
        connector_c,
        connector_z,
        connector_0,
        connector_1,
        connector_2,
        connector_3,
        connector_4,
        connector_5,
        DEPOSITOR_EVM_ADDRESS.to_string(),
        WITHDRAWER_EVM_ADDRESS.to_string(),
    );
}

pub fn get_groth16_proof() -> (VerifyingKey, Proof, PublicInputs) {
    load_proof_from_file("chunker_data/dummy_proof.json")
}

pub fn get_tapscripts() -> Vec<Script> {
    load_assert_tapscripts_from_file(0, g16::N_TAPLEAVES - 1, "tapscripts/tapscript")
}

pub fn get_signed_assertions() -> WotsSignatures {
    load_all_signed_assertions_from_file("signed_assertions/signed_assertion")
}   

pub fn corrupt_assertions(signed_assertions: &mut WotsSignatures, index: usize) {
    let (_, wots_sk) = get_wots_keys();
    corrupt_signed_assertions(&wots_sk, signed_assertions, index);
}   

pub fn get_wots_keys() -> (WotsPublicKeys, WotsSecretKeys) {
    generate_wots_keys_from_secrets(TEST_SECRET)
}
