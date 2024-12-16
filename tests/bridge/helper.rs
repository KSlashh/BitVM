extern crate bitcoin_origin;
extern crate bitcoin_hashes_origin;
extern crate bitcoin_hashes;

// use hex;
use tokio::time::{sleep, Duration};
use core::str::FromStr;
use bitcoin_hashes::Hash;
use bitcoin_hashes_origin::hex::{FromHex, ToHex};
use bitcoincore_rpc::{Client, Auth, RpcApi};
use bitcoin::consensus::encode;
// use bitcoincore_rpc_json as json;
use bitcoin::{
    Address, Amount, Network, OutPoint, Transaction, TxIn, 
    TxOut, Txid, ScriptBuf, Witness, Sequence,
    EcdsaSighashType, secp256k1::{Message, SecretKey, rand}, sighash::SighashCache,
};
use bitvm::treepp::*;
use bitvm::bridge::scripts;
use bitvm::bridge::contexts::base;

pub const TX_WAIT_TIME: u64 = 1; // in seconds
pub const FAUCET_RPCWALLET: &str = "main";
pub const RPCUSER: &str = "test";
pub const RPCPASSWORD: &str = "test";
pub const REGTEST_URL: &str = "http://127.0.0.1:18443";

pub fn dead_address() -> Address {
    Address::p2sh(&script!{OP_RETURN}.compile(), Network::Regtest).unwrap()
} 

pub async fn wait_tx() {
    sleep(Duration::from_secs(TX_WAIT_TIME)).await;
} 

pub fn tx_wrapper(tx: &Transaction) -> String {
    encode::serialize_hex(tx)
}

pub fn address_wrapper(address: &Address) -> bitcoin_origin::Address {
    bitcoin_origin::Address::from_str(&address.to_string()).unwrap()
}

pub fn amount_wrapper(amount: Amount) -> bitcoin_origin::Amount {
    bitcoin_origin::Amount::from_sat(amount.to_sat())
}

pub fn txid_wrapper(txid: Txid) -> bitcoin_origin::Txid {
    let hash_hex = txid.to_hex();
    bitcoin_origin::Txid::from_hash(bitcoin_hashes_origin::sha256d::Hash::from_hex(&hash_hex).unwrap())
}

pub fn txid_unwrapper(txid: bitcoin_origin::Txid) -> Txid {
    let mut hash_bytes = hex::decode(txid.to_hex()).unwrap();
    hash_bytes.reverse();
    Txid::from_slice(hash_bytes.as_slice()).unwrap()
}

pub async fn new_rpc_client() -> Client {
    let rpc = Client::new(REGTEST_URL, Auth::UserPass(RPCUSER.to_string(), RPCPASSWORD.to_string())).unwrap();
    // rpc.load_wallet(FAUCET_RPCWALLET);
    rpc
}

pub fn broadcast_tx(rpc: &Client, tx: &Transaction) {
    rpc.send_raw_transaction(tx_wrapper(tx)).expect("fail to broadcast_tx");
}

pub fn mint_block(rpc: &Client, block_num: u64) {
    rpc.generate_to_address(block_num, &address_wrapper(&dead_address())).expect("fail to mint block");
}

pub fn validate_tx(rpc: &Client, txid: Txid) {
    let res = rpc.get_tx_out(&txid_wrapper(txid), 0, None).expect("fail to get tx_info");
    assert!(res.unwrap().confirmations > 0, "invalid tx: no enough comfirmation");
}

pub fn generate_stub_outpoint_batch(
    rpc: &Client,
    funding_utxo_addresses: &Vec<Address>,
    input_values: &Vec<Amount>,
) -> Vec<OutPoint> { 
    // init fund
    assert!(funding_utxo_addresses.len() == input_values.len());
    let res_num = funding_utxo_addresses.len() as u32;
    let total_amount = input_values.iter().map(|amount| amount.to_sat()).sum::<u64>() + 1_000_000;
    let network = Network::Regtest;
    let tmp_secret = SecretKey::new(&mut rand::thread_rng()).secret_bytes().to_hex();
    let (secp, keypair, public_key) = base::generate_keys_from_secret(network, &tmp_secret);
    let bulk_address = scripts::generate_pay_to_pubkey_script_address(network, &public_key);
    let fund_outpoint = fund_utxo(rpc, &bulk_address, Amount::from_sat(total_amount));  
    
    // construct bulk tx
    let bulk_input = vec![
        TxIn {
            previous_output: fund_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        },
    ];
    let bulk_output = funding_utxo_addresses.iter()
        .zip(input_values.iter())
        .map(|(addr, amt)| TxOut { value: *amt, script_pubkey: addr.script_pubkey()})
        .collect();
    let mut bulk_tx = Transaction{
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: bulk_input,
        output: bulk_output,
    };

    // sign 
    let scr = scripts::generate_pay_to_pubkey_script(&public_key);
    let value = Amount::from_sat(total_amount);
    let sighash_type = EcdsaSighashType::All;
    let mut sighash_cache = SighashCache::new(&mut bulk_tx);
    let sighash = sighash_cache
        .p2wsh_signature_hash(0, &scr, value, sighash_type)
        .expect("Failed to construct sighash");
    let signature = secp.sign_ecdsa(&Message::from(sighash), &keypair.secret_key());
    let signature = bitcoin::ecdsa::Signature {
        signature,
        sighash_type,
    };
    bulk_tx.input[0].witness.push_ecdsa_signature(&signature);
    bulk_tx.input[0].witness.push(scr);

    // broadcast
    mint_block(rpc, 1);
    broadcast_tx(rpc, &bulk_tx);
    let txid = bulk_tx.compute_txid();
    (0..res_num).map(|vout| OutPoint{txid,vout}).collect()
}

pub fn generate_stub_outpoint(
    rpc: &Client,
    funding_utxo_address: &Address,
    input_value: Amount,
) -> OutPoint {
    fund_utxo(rpc, funding_utxo_address, input_value)
}

pub fn fund_utxo(rpc: &Client, address: &Address, amount: Amount) -> OutPoint {
    let txid = rpc.send_to_address(&address_wrapper(address), amount_wrapper(amount), None, None, None, None, None, None).unwrap();
    let txinfo = rpc.get_transaction(&txid, None).unwrap();
    OutPoint {
        txid: txid_unwrapper(txid),
        vout: txinfo.details[0].vout,
    }
}

#[tokio::test]
pub async fn main() {
    let rpc = new_rpc_client().await;

    let address = Address::from_str("bcrt1pemjrv7terwkk26n2m9nc8fm5pc43elnvrcq7leml3cnt2nayvhus9hjfpy").unwrap().assume_checked();
    let amount = Amount::from_btc(1.0).unwrap();

    let res = fund_utxo(&rpc, &address, amount);
    dbg!(res);
}
