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
use bitcoin::{Address, Amount, OutPoint, Network, Transaction, Txid};
use bitvm::treepp::*;

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
