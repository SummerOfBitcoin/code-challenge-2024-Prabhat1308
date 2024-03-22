use byteorder::WriteBytesExt;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use libsecp256k1::{Message, PublicKey, SecretKey, Signature};
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::Path;


struct Transaction {
  version : u16,
  locktime : u32,
  vin : Vec<Input>,
  vout : Vec<Output>,
}

struct Input {

}

struct Output {
    
}

fn run() {

    for entry in fs::read_dir("../../mempool") {

    }
}
 
