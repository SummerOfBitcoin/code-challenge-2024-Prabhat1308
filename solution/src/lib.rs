use byteorder::WriteBytesExt;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use libsecp256k1::{Message, PublicKey, SecretKey, Signature};
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::Path;

#[derive(Deserialize)]
struct Transaction {
  version : u32 ,
  locktime : u32 ,
  vin : Vec<Input>,
  vout : Vec<Output>,
}

#[derive(Deserialize)]
struct Input {
  txid : String ,
  vout : u32 ,
  prevout : Vec<PrevOut> ,
  scriptsig: String,
  scriptsig_asm: String,
  witness : Vec<String>,
  is_coinbase : bool,
  sequence : u32 ,
}


#[derive(Deserialize)]
struct PrevOut {
  scriptpubkey: String,
  scriptpubkey_asm: String,
  scriptpubkey_type: String,
  scriptpubkey_address: String,
  value: u32 ,
  
}

#[derive(Deserialize)]
struct Output {
  scriptpubkey: String,
  scriptpubkey_asm: String,
  scriptpubkey_type: String,
  scriptpubkey_address: String,
  value: u32 ,
}


pub fn run() {

  // let mut total_tx : u32 = 0; 
  // let mut ver_1 : u32 =0;
  // let mut ver_2 : u32 =0;

    for entry in fs::read_dir("../mempool").unwrap() {
        
        let tx : Transaction = serde_json::from_str(&fs::read_to_string(entry.unwrap().path()).unwrap()).unwrap();
        
        let tx_version = tx.version;
        
        // if tx_version == 1 {
        //     ver_1 += 1;
        // } else if tx_version == 2 {
        //     ver_2 += 1;
        // }
        // total_tx += 1;
    }

    // println!("Total transactions: {}", total_tx);
    // println!("Version 1 transactions: {}", ver_1);
    // println!("Version 2 transactions: {}", ver_2);

    /*
    Total transactions: 8131
    Version 1 transactions: 2259
    Version 2 transactions: 5872 
    */
}
 
