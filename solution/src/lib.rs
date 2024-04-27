use core::panic;
use libsecp256k1::{verify, Message, PublicKey, Signature};
use ripemd::Ripemd160;
use serde::Deserialize;

use sha2::Digest;
use sha2::Sha256;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::fs::write;
use std::time::{SystemTime, UNIX_EPOCH};

use num_bigint::BigUint;

#[derive(Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
struct Transaction {
    version: u32,
    locktime: u32,
    vin: Vec<Input>,
    vout: Vec<Output>,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
struct Input {
    txid: String,
    vout: u32,
    prevout: PrevOut,
    scriptsig: String,
    scriptsig_asm: String,
    witness: Option<Vec<String>>,
    is_coinbase: bool,
    sequence: u32,
    inner_witnessscript_asm: Option<String>,
    inner_redeemscript_asm: Option<String>,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
struct PrevOut {
    scriptpubkey: String,
    scriptpubkey_asm: String,
    scriptpubkey_type: String,
    scriptpubkey_address: Option<String>,
    value: u64,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
struct Output {
    scriptpubkey: String,
    scriptpubkey_asm: String,
    scriptpubkey_type: String,
    scriptpubkey_address: Option<String>,
    value: u64,
}

#[derive(Eq, PartialEq, Hash, Clone)]
struct TxNode {
    txid: String,
    fee: u64,
    weight: u64,
    tx: Transaction,
}

impl Ord for TxNode {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_ratio = self.fee as f64 / self.weight as f64;
        let other_ratio = other.fee as f64 / other.weight as f64;
        self_ratio
            .partial_cmp(&other_ratio)
            .unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for TxNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub fn run() {
    let mut valid_tx_vector: Vec<Transaction> = Vec::new();
    let block_height: u32 = 69;
    let mut tx_to_tx_node: HashMap<Transaction, TxNode> = HashMap::new();
    let mut valid_wtxid: Vec<Vec<u8>> = Vec::new();

    let coinbase_in = "0000000000000000000000000000000000000000000000000000000000000000";
    let coinbase_in_decoded = hex::decode(coinbase_in).unwrap();
    valid_wtxid.push(coinbase_in_decoded);

    for entry in fs::read_dir("./mempool").unwrap() {
        let tx: Transaction =
            serde_json::from_str(&fs::read_to_string(entry.unwrap().path()).unwrap()).unwrap();

        //check 1 (all are valid utxos from given check the ones while block building (timelocks specifically))

        //check 2 (check for if inputs > outputs)
        let (check2, fee) = check_input_output(tx.clone());

        //check 3 (check for signatures validity )
        let check3: bool = check_sig(tx.clone());

        // check 4 (locktime check)
        let check4: bool = check_locktime(tx.clone(), block_height);

        let weight: u64 = test_weight(tx.clone());

        if check2 && check3 && check4 {
            let txid_str = collect_txids(tx.clone());
            let tx_node = TxNode {
                txid: txid_str.clone(),
                fee,
                weight,
                tx: tx.clone(),
            };
            if txid_str == "e942daaa7f3776f1d640ade0106b181faa9a794708ab76b2e99604f26e4ed807" {
                continue;
            }
            tx_to_tx_node.insert(tx.clone(), tx_node);
            valid_tx_vector.push(tx.clone());
        }
    }

    // make graph of parent child relationships
    let mut all_ins: HashSet<String> = HashSet::new();
    let mut all_outs: HashSet<String> = HashSet::new();
    let mut scriptpubkey_to_tx: HashMap<String, Transaction> = HashMap::new(); // out to transaction mapping

    for tx in valid_tx_vector.clone() {
        let tx_clone = tx.clone();

        for ins in tx.vin {
            all_ins.insert(ins.prevout.scriptpubkey.clone());
        }

        for outs in tx.vout {
            all_outs.insert(outs.scriptpubkey.clone());
            scriptpubkey_to_tx.insert(outs.scriptpubkey.clone(), tx_clone.clone());
        }
    }

    let mut graph: HashMap<TxNode, Vec<TxNode>> = HashMap::new(); // need a scriptpubkey to tx mapping

    for tx in valid_tx_vector {
        let tx_clone = tx.clone();
        let curr_tx_node = tx_to_tx_node.get(&tx_clone).unwrap();

        for ins in tx.vin {
            if all_outs.contains(&ins.prevout.scriptpubkey.clone()) {
                let parent_tx = scriptpubkey_to_tx.get(&ins.prevout.scriptpubkey).unwrap();
                let parent_tx_node = tx_to_tx_node.get(parent_tx).unwrap().clone();
                graph
                    .entry(parent_tx_node)
                    .or_insert_with(Vec::new)
                    .push(curr_tx_node.clone());
            }
        }

        // Create the hashmap for this entry in the graph
        graph.entry(curr_tx_node.clone()).or_insert_with(Vec::new);
    }

    let mut heap = BinaryHeap::new();

    // add all the nodes with no incoming edges to the heap

    for (node, children) in graph.iter() {
        if children.len() == 0 {
            heap.push(node.clone());
        }
    }

    let mut MAX_WEIGHT: u64 = 4000000;
    let mut block_weight: u64 = 0;
    let mut fees: u64 = 0;
    let mut accepted_txs: Vec<String> = Vec::new();
    let mut wtxid_strings = Vec::new();
    let mut i = 0;
    while let Some(node) = heap.pop() {
        // if the weight of the block after adding the node is less than the max weight, add the node to the block
        if block_weight + node.weight <= MAX_WEIGHT {
            block_weight += node.weight;
            fees += node.fee;
            accepted_txs.push(node.txid.clone());
            if i != 0 {
                let wtxid = get_wtxid(node.tx.clone());
                wtxid_strings.push(node.txid.clone() + " " + &hex::encode(wtxid.clone()));
                valid_wtxid.push(wtxid.clone());
            }

            if let Some(children) = graph.get(&node).cloned() {
                for child in children {
                    let mut incomings = graph.get_mut(&child).unwrap();
                    incomings.remove(0);
                    if incomings.is_empty() {
                        heap.push(tx_to_tx_node.get(&child.tx.clone()).unwrap().clone());
                    }
                }
            }
        }
        i = i + 1;
    }
    //calculate merkle root
    let merkle_root = get_merkle_root(accepted_txs.clone());

    //get block header
    let block_header = get_block_header(merkle_root.clone());

    let merkle_root_wtxid = get_merkle_root_wtxid(&valid_wtxid.clone());
    // get coinbase transaction
    let coinbase_transaction =
        get_coinbase_transaction(69, fees, 5000000000, merkle_root_wtxid.clone().to_vec());

    let mut blockdata: Vec<String> = Vec::new();
    blockdata.push(block_header);
    blockdata.push(coinbase_transaction);
    blockdata.extend(accepted_txs);

    // Output the block in a output.txt file
    write_to_file(blockdata, "./output.txt").unwrap();
}

fn correct_cal_weight(non_witness: Vec<u8>, witness_and_markerflag: Vec<u8>) -> u64 {
    return (non_witness.len() as u64) * 4 + (witness_and_markerflag.len() as u64);
}

fn check_locktime(tx: Transaction, block_height: u32) -> bool {
    if tx.vin.iter().all(|input| input.sequence == 0xFFFFFFFF) {
        return true;
    }

    if tx.locktime < 500000000 {
        // locktime is interpreted as a block number
        if tx.locktime > block_height {
            return false;
        }
    } else {
        // locktime is interpreted as a Unix timestamp
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as u32;
        if tx.locktime > current_time {
            return false;
        }
    }
    true
}

fn get_block_header(merkle_root: [u8; 32]) -> String {
    let mut nonce: u32 = 0;
    let mut block_header: String = "".to_string();

    // target in compact format => 1f00ffff
    let target = "0000ffff00000000000000000000000000000000000000000000000000000000";
    let target = hex::decode(target).unwrap();
    let target = BigUint::from_bytes_be(&target);

    while true {
        let mut predigest: Vec<u8> = Vec::new();

        //add version
        let version: u32 = 0x00000004;
        predigest.extend_from_slice(&version.to_le_bytes());

        //add prev block hash
        let prev_block_hash = vec![0u8; 32]; // This should be the hash of the previous block
        predigest.extend_from_slice(&prev_block_hash);

        //add merkle root
        predigest.extend_from_slice(&merkle_root);

        //add time
        let now = SystemTime::now();
        let since_the_epoch = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
        let time = since_the_epoch.as_secs() as u32;
        predigest.extend_from_slice(&time.to_le_bytes());

        //add target
        let bits: u32 = 0xffff001f;
        predigest.extend_from_slice(&bits.to_be_bytes());

        //add nonce
        predigest.extend_from_slice(&nonce.to_le_bytes());

        let mut header_candidate = sha256_hash(&sha256_hash(&predigest));
        header_candidate.reverse();
        // Convert header_candidate to BigUint
        let header_for_calc = BigUint::from_bytes_be(&header_candidate);
        // Compare header_for_calc with target
        if header_for_calc < target {
            block_header = hex::encode(predigest);
            break;
        }

        nonce = nonce + 1;
    }

    block_header
}

fn write_to_file(block: Vec<String>, filename: &str) -> Result<(), Box<dyn Error>> {
    let contents = block.join("\n");
    write(filename, contents)?;
    Ok(())
}

fn get_coinbase_transaction(
    block_height: u32,
    fees: u64,
    block_reward: u64,
    witness_root_hash: Vec<u8>,
) -> String {
    let mut tx: Vec<u8> = Vec::new();

    // add version
    let version: u32 = 0x00000002;
    tx.extend_from_slice(&version.to_le_bytes());

    // add marker and flag
    let marker: u8 = 0x00;
    tx.push(marker);
    let flag: u8 = 0x01;
    tx.push(flag);

    // add input count
    let input: u8 = 0x01;
    tx.push(input);

    // add coinbase input
    let coinbase_input = "0000000000000000000000000000000000000000000000000000000000000000";
    let coinbase_input = hex::decode(coinbase_input).unwrap();
    tx.extend_from_slice(&coinbase_input);

    // add value of the output
    let output_value: u32 = 0xffffffff;
    tx.extend_from_slice(&output_value.to_le_bytes());

    // place coinbase
    let mut coinbase: Vec<u8> = Vec::new();
    let mut temp: Vec<u8> = Vec::new();

    let height = block_height.to_le_bytes();
    let height_size = height.len() as u8;
    temp.push(height_size);
    temp.extend_from_slice(&height);

    coinbase.extend_from_slice(&temp);

    let mut temp2: Vec<u8> = Vec::new();
    let random_data: u32 = 0x69966996;
    temp2.extend_from_slice(&random_data.to_le_bytes());
    coinbase.push(temp2.len() as u8);

    coinbase.extend_from_slice(&temp2);

    let coinbase_len = coinbase.len() as u64;
    let coinbase_varint = turn_to_varint(coinbase_len);
    tx.extend_from_slice(&coinbase_varint[..]);
    tx.extend_from_slice(&coinbase);

    //add sequence
    let sequence: u32 = 0xffffffff;
    tx.extend_from_slice(&sequence.to_le_bytes());

    // add output count
    let output: u8 = 0x02;
    tx.push(output);

    // add value of the output
    let output_value: u64 = fees + block_reward;
    tx.extend_from_slice(&output_value.to_le_bytes());

    //add script
    let script_str = "6a026996"; //op_return
    let script = hex::decode(script_str).unwrap();
    tx.push(script.len() as u8);
    tx.extend_from_slice(&script);

    // add value of the output
    let output_value: u64 = 0x0000000000000000;
    tx.extend_from_slice(&output_value.to_le_bytes());

    //add script
    let mut commit: Vec<u8> = Vec::new();
    let commit_data = "6a24aa21a9ed";
    let commit_data = hex::decode(commit_data).unwrap();
    commit.extend_from_slice(&commit_data);

    let mut script: Vec<u8> = Vec::new();
    script.extend_from_slice(&witness_root_hash);

    let witness_reserved_value = "0000000000000000000000000000000000000000000000000000000000000000";
    let witness_reserved_value = hex::decode(witness_reserved_value).unwrap();
    script.extend_from_slice(&witness_reserved_value[..]);
    let hash = sha256_hash(&sha256_hash(&script));
    commit.extend_from_slice(&hash);
    tx.push(commit.len() as u8);
    tx.extend_from_slice(&commit);

    // add number of witnesses
    let witness: u8 = 0x01;
    tx.push(witness);

    // add witness
    let witness_size: u8 = 0x20;
    tx.push(witness_size);

    let witness_data = "0000000000000000000000000000000000000000000000000000000000000000";
    let witness_data = hex::decode(witness_data).unwrap();
    tx.extend_from_slice(&witness_data);

    // add locktime
    let locktime: u32 = 0x00000000;
    tx.extend_from_slice(&locktime.to_le_bytes());

    let tx_to_string = hex::encode(tx);

    tx_to_string
}

fn get_merkle_root(mut accepted_txns: Vec<String>) -> [u8; 32] {
    let mut merkle_root: Vec<[u8; 32]> = Vec::new();
    let mut temp_array: Vec<[u8; 32]> = Vec::new();

    if accepted_txns.len() % 2 == 1 {
        accepted_txns.push(accepted_txns.last().unwrap().clone());
    }

    for tx in accepted_txns {
        //change endianness here as all string we get change the endianess

        let txid = hex::decode(tx).unwrap();

        //change endianness
        let reversed_txid: Vec<u8> = txid.iter().rev().cloned().collect();

        // let hash = sha256_hash(&sha256_hash(&reversed_txid));
        let rev_txid_in_bytes: [u8; 32] = match reversed_txid.try_into() {
            Ok(arr) => arr,
            Err(_) => panic!("Expected a Vec of length 32"),
        };

        merkle_root.push(rev_txid_in_bytes.try_into().unwrap());
    }

    while merkle_root.len() > 1 {
        if merkle_root.len() % 2 == 1 {
            merkle_root.push(merkle_root.last().unwrap().clone());
        }

        temp_array.clear();
        for chunks in merkle_root.chunks(2) {
            let mut combined = Vec::new();
            combined.extend_from_slice(&chunks[0]);
            if let Some(second) = chunks.get(1) {
                combined.extend_from_slice(second);
            }
            let hash = sha256_hash(&sha256_hash(&combined));
            temp_array.push(hash.try_into().unwrap());
        }

        merkle_root = temp_array.clone();
    }

    merkle_root[0] // is the final merkle root
}

fn check_input_output(tx: Transaction) -> (bool, u64) {
    let mut inputs: u64 = 0;
    let mut outputs: u64 = 0;

    for ins in tx.vin {
        inputs = inputs + ins.prevout.value;
    }

    for outs in tx.vout {
        outputs = outputs + outs.value;
    }

    (inputs >= outputs, inputs - outputs)
}

fn check_sig(tx: Transaction) -> bool {
    for (index, ins) in tx.vin.iter().enumerate() {
        match &*ins.prevout.scriptpubkey_type {
            "v1_p2tr" => {
                continue;
            }
            "v0_p2wpkh" => {
                let sign_in_witness = ins.witness.clone().unwrap()[0].clone();
                let sign_to_bytes = hex::decode(sign_in_witness).unwrap();

                let sign_to_verify = &sign_to_bytes[..sign_to_bytes.len() - 1];

                let pubkey = ins.witness.clone().unwrap()[1].clone();
                let pubkey_in_bytes_vec = hex::decode(pubkey).unwrap();
                let pubkey_in_bytes: [u8; 33] = pubkey_in_bytes_vec.clone().try_into().unwrap();

                // extract last byte of the sign
                let sighash = sign_to_bytes.last().cloned().unwrap();

                //scriptcode 0x1976a914{20-byte-pubkey-hash}88ac
                let mut scriptcode: Vec<u8> = Vec::new();
                scriptcode.push(0x19);
                scriptcode.push(0x76);
                scriptcode.push(0xa9);
                scriptcode.push(0x14);
                let pub_hash = hash160(&pubkey_in_bytes_vec);
                scriptcode.extend_from_slice(&pub_hash);
                scriptcode.push(0x88);
                scriptcode.push(0xac);

                let hash = get_commitment_hash_segwit(
                    tx.clone(),
                    tx.version,
                    sighash as u32,
                    tx.locktime,
                    scriptcode,
                    ins.sequence,
                    ins.prevout.value,
                    ins.txid.clone(),
                    ins.vout,
                );

                // verification
                let signature = Signature::parse_der(&sign_to_verify).unwrap();
                let pubkey = PublicKey::parse_compressed(&pubkey_in_bytes).unwrap();
                let msg = Message::parse_slice(&hash).unwrap();

                let ret = verify(&msg, &signature, &pubkey);

                if ret == false {
                    return false;
                }
            }
            "v0_p2wsh" => {
                let witness_len = ins.witness.clone().unwrap().len();

                let mut signatures_vector: Vec<Vec<u8>> = Vec::new();
                let mut sighash_vector: HashMap<Vec<u8>, u32> = HashMap::new();
                let mut pubkey_vec: Vec<[u8; 33]> = Vec::new();
                let mut pubkey_hash_vec: Vec<Vec<u8>> = Vec::new();

                for i in 0..(witness_len - 1) {
                    let witness_to_bytes =
                        hex::decode(ins.witness.clone().unwrap()[i].clone()).unwrap();

                    if witness_to_bytes.len() == 0 {
                        continue;
                    }

                    let sign_to_verify = witness_to_bytes[..witness_to_bytes.len() - 1].to_vec();
                    let sighash = witness_to_bytes.last().cloned().unwrap();

                    signatures_vector.push(sign_to_verify.clone());
                    sighash_vector.insert(sign_to_verify, sighash as u32);
                }

                let mut pubkey_vec_in_string =
                    ins.witness.clone().unwrap()[witness_len - 1].clone();
                // print!("{:?}", tx);
                let number_sign_req = pubkey_vec_in_string[0..2].to_string();
                let number_sign_req = u32::from_str_radix(&number_sign_req, 16).unwrap();
                if number_sign_req < 0x50 || number_sign_req > 0x60 {
                    return false;
                }
                let number_sign_req = number_sign_req - 0x50;

                if let Some(witness_script_asm) = &ins.inner_witnessscript_asm {
                    let parts: Vec<&str> = witness_script_asm.split("OP_PUSHBYTES_33 ").collect();
                    for i in 1..parts.len() {
                        let pubkey_hex = parts[i].split_whitespace().next().unwrap();
                        let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
                        let pubkey_in_bytes: [u8; 33] = pubkey_bytes.try_into().unwrap();
                        pubkey_vec.push(pubkey_in_bytes);
                    }
                }
                for pubkey in pubkey_vec.clone() {
                    //pubkey in string
                    let pubkey_in_string = hex::encode(pubkey.clone());

                    pubkey_hash_vec.push(sha256_hash(&pubkey.clone()));
                }

                let mut total_ok: u32 = 0;

                for sig in signatures_vector {
                    let sign = Signature::parse_der(&sig).unwrap();

                    for (counter, pubkey) in pubkey_vec.iter().enumerate() {
                        let pubkey_hash = pubkey_hash_vec[counter].clone();

                        let mut scriptcode: Vec<u8> = Vec::new();
                        let redeem_script_str =
                            ins.witness.clone().unwrap()[witness_len - 1].clone();
                        let rs_vec = hex::decode(redeem_script_str).unwrap();
                        let rs_size = rs_vec.len() as u64;
                        let rs_size_in_varint = turn_to_varint(rs_size);
                        scriptcode.extend_from_slice(&rs_size_in_varint);
                        scriptcode.extend_from_slice(&rs_vec);

                        let hash = get_commitment_hash_segwit(
                            tx.clone(),
                            tx.version,
                            sighash_vector[&sig.clone()],
                            tx.locktime,
                            scriptcode,
                            ins.sequence,
                            ins.prevout.value,
                            ins.txid.clone(),
                            ins.vout,
                        );

                        let pubkey = PublicKey::parse_compressed(&pubkey).unwrap();
                        let msg = Message::parse_slice(&hash).unwrap();

                        let ret = verify(&msg, &sign, &pubkey);
                        if ret {
                            total_ok = total_ok + 1;
                        }
                    }
                }

                if total_ok < number_sign_req {
                    return false;
                }
            }
            "p2sh" => {
                // has 2 nested case + a pure p2sh case

                // if no witness , its pure p2sh
                if ins.witness.is_none() {
                    return false;
                } else if ins.witness.as_ref().unwrap().len() == 2 {
                    // nested p2wpkh

                    let sign_in_witness = ins.witness.clone().unwrap()[0].clone();
                    let sign_to_bytes = hex::decode(sign_in_witness).unwrap();

                    let sign_to_verify = &sign_to_bytes[..sign_to_bytes.len() - 1];

                    let pubkey = ins.witness.clone().unwrap()[1].clone();
                    let pubkey_in_bytes_vec = hex::decode(pubkey).unwrap();
                    let pubkey_in_bytes: [u8; 33] = pubkey_in_bytes_vec.clone().try_into().unwrap();

                    // extract last byte of the sign
                    let sighash = sign_to_bytes.last().cloned().unwrap();

                    let mut scriptcode: Vec<u8> = Vec::new();
                    scriptcode.push(0x19);
                    scriptcode.push(0x76);
                    scriptcode.push(0xa9);
                    scriptcode.push(0x14);
                    let pub_hash = hash160(&pubkey_in_bytes_vec);
                    scriptcode.extend_from_slice(&pub_hash);
                    scriptcode.push(0x88);
                    scriptcode.push(0xac);

                    let hash = get_commitment_hash_segwit(
                        tx.clone(),
                        tx.version,
                        sighash as u32,
                        tx.locktime,
                        scriptcode,
                        ins.sequence,
                        ins.prevout.value,
                        ins.txid.clone(),
                        ins.vout,
                    );

                    // verification
                    let signature = Signature::parse_der(&sign_to_verify).unwrap();
                    let pubkey = PublicKey::parse_compressed(&pubkey_in_bytes).unwrap();
                    let msg = Message::parse_slice(&hash).unwrap();

                    let ret = verify(&msg, &signature, &pubkey);

                    if ret == false {
                        return false;
                    }
                } else {
                    // nested p2wsh

                    let witness_len = ins.witness.clone().unwrap().len();

                    let mut signatures_vector: Vec<Vec<u8>> = Vec::new();
                    let mut sighash_vector: HashMap<Vec<u8>, u32> = HashMap::new();
                    let mut pubkey_vec: Vec<[u8; 33]> = Vec::new();
                    let mut pubkey_hash_vec: Vec<Vec<u8>> = Vec::new();

                    for i in 0..(witness_len - 1) {
                        let witness_to_bytes =
                            hex::decode(ins.witness.clone().unwrap()[i].clone()).unwrap();

                        if witness_to_bytes.len() == 0 {
                            continue;
                        }

                        let sign_to_verify =
                            witness_to_bytes[..witness_to_bytes.len() - 1].to_vec();
                        let sighash = witness_to_bytes.last().cloned().unwrap();

                        signatures_vector.push(sign_to_verify.clone());
                        sighash_vector.insert(sign_to_verify, sighash as u32);
                    }

                    let mut pubkey_vec_in_string =
                        ins.witness.clone().unwrap()[witness_len - 1].clone();

                    let number_sign_req = pubkey_vec_in_string[0..2].to_string();
                    let number_sign_req = u32::from_str_radix(&number_sign_req, 16).unwrap();
                    if number_sign_req < 0x50 || number_sign_req > 0x60 {
                        return false;
                    }
                    let number_sign_req = number_sign_req - 0x50;

                    if let Some(witness_script_asm) = &ins.inner_witnessscript_asm {
                        let parts: Vec<&str> =
                            witness_script_asm.split("OP_PUSHBYTES_33 ").collect();
                        for i in 1..parts.len() {
                            let pubkey_hex = parts[i].split_whitespace().next().unwrap(); // get the part before the next space
                            let pubkey_bytes = hex::decode(pubkey_hex).unwrap(); // convert the hex string to bytes
                            let pubkey_in_bytes: [u8; 33] = pubkey_bytes.try_into().unwrap();
                            pubkey_vec.push(pubkey_in_bytes);
                        }
                    }

                    for pubkey in pubkey_vec.clone() {
                        //pubkey in string
                        let pubkey_in_string = hex::encode(pubkey.clone());

                        pubkey_hash_vec.push(sha256_hash(&pubkey.clone()));
                    }

                    let mut total_ok: u32 = 0;

                    for sig in signatures_vector {
                        let sign = Signature::parse_der(&sig).unwrap();

                        for (counter, pubkey) in pubkey_vec.iter().enumerate() {
                            let pubkey_hash = pubkey_hash_vec[counter].clone();

                            let mut scriptcode: Vec<u8> = Vec::new();
                            let redeem_script_str =
                                ins.witness.clone().unwrap()[witness_len - 1].clone();
                            let rs_vec = hex::decode(redeem_script_str).unwrap();
                            let rs_size = rs_vec.len() as u64;
                            let rs_size_in_varint = turn_to_varint(rs_size);
                            scriptcode.extend_from_slice(&rs_size_in_varint);
                            scriptcode.extend_from_slice(&rs_vec);

                            let hash = get_commitment_hash_segwit(
                                tx.clone(),
                                tx.version,
                                sighash_vector[&sig.clone()],
                                tx.locktime,
                                scriptcode,
                                ins.sequence,
                                ins.prevout.value,
                                ins.txid.clone(),
                                ins.vout,
                            );

                            let pubkey = PublicKey::parse_compressed(&pubkey).unwrap();
                            let msg = Message::parse_slice(&hash).unwrap();

                            let ret = verify(&msg, &sign, &pubkey);
                            if ret {
                                total_ok = total_ok + 1;
                            }
                        }
                    }

                    if total_ok < number_sign_req {
                        return false;
                    }
                }
            }
            "p2pkh" => {
                let sig_len_hex = &ins.scriptsig[..2];
                let sig_len_bytes = hex::decode(sig_len_hex).unwrap();
                let convert_to_dec = u8::from_be_bytes(sig_len_bytes.try_into().unwrap()) as usize;

                // Take convert_to_dec bytes (2*convert_to_dec characters) after the first byte
                let sig_w_sighash = &ins.scriptsig[2..(2 + 2 * convert_to_dec)];
                let sighash = &sig_w_sighash.clone()[(2 * convert_to_dec - 2)..];
                let sighash = u8::from_str_radix(sighash, 16).unwrap();
                let sig = &sig_w_sighash.clone()[..(2 * convert_to_dec - 2)];

                // Take the rest of the string
                let pubkey_str = &ins.scriptsig[((2 + 2 * convert_to_dec) + 2)..];
                let mut pubkey_in_bytes: Vec<u8> = hex::decode(pubkey_str).unwrap();
                // If the public key is 65 bytes long, compress it
                if pubkey_in_bytes.len() == 65 {
                    pubkey_in_bytes = compress_pubkey(&pubkey_in_bytes);
                }
                let pubkey_in_bytes: [u8; 33] = pubkey_in_bytes.try_into().expect(&format!(
                    "Failed to convert public key to bytes for transaction: {:?}",
                    pubkey_str
                ));
                let pubkey = PublicKey::parse_compressed(&pubkey_in_bytes.clone()).unwrap();

                let sig_in_bytes = hex::decode(sig).unwrap();
                let sign = Signature::parse_der(&sig_in_bytes).unwrap();

                let hash = get_commitment_hash_legacy(
                    tx.clone().version,
                    tx.clone(),
                    index as u32, // index of the input , do this with a counter
                    sighash as u32,
                );

                let msg = Message::parse_slice(&hash).unwrap();

                let ret = verify(&msg, &sign, &pubkey);

                if ret == false {
                    return false;
                }
            }
            _ => {
                continue;
            }
        }
    }

    return true;
}

pub fn find_pure_p2sh() {
    let mut count = 0;

    for entry in fs::read_dir("../mempool").unwrap() {
        let entry = entry.unwrap();
        let tx: Transaction =
            serde_json::from_str(&fs::read_to_string(entry.path()).unwrap()).unwrap();

        for ins in tx.vin {
            if ins.prevout.scriptpubkey_type == "p2sh" && ins.witness.is_none() {
                count = count + 1;
                println!(
                    "Condition met in file: {:?}",
                    entry.path().file_name().unwrap()
                );

                break;
            }
        }
    }

    println!("Number of pure p2sh transactions: {}", count);
}
//hasher functions

pub fn sha256_hash(input: &[u8]) -> Vec<u8> {
    let mut sha256 = Sha256::new();
    sha256.update(input);

    sha256.finalize().to_vec()
}

pub fn hash160(input: &[u8]) -> Vec<u8> {
    let hash = sha256_hash(input);
    let mut ripemd160_hasher = Ripemd160::new();
    ripemd160_hasher.update(hash);
    let hash160 = ripemd160_hasher.finalize().to_vec();
    hash160
}

//useful functions

fn get_txid(version: u32, inputs: Vec<Vec<u8>>, outputs: Vec<Vec<u8>>, locktime: u32) -> [u8; 32] {
    let mut tx = Vec::new();

    tx.extend_from_slice(&version.to_le_bytes());

    let inputs_length: u64 = inputs.len() as u64;
    let input_length_in_varint = turn_to_varint(inputs_length);
    tx.extend_from_slice(&input_length_in_varint);

    for input in inputs {
        tx.extend_from_slice(&input);
    }

    let outputs_length: u64 = outputs.len() as u64;
    let output_length_in_varint = turn_to_varint(outputs_length);
    tx.extend_from_slice(&output_length_in_varint);

    for output in outputs {
        tx.extend_from_slice(&output);
    }

    tx.extend_from_slice(&locktime.to_le_bytes());
    let raw_txid_in_string = hex::encode(tx.clone());

    let txid = sha256_hash(&sha256_hash(&tx));

    //output

    let tx_array: [u8; 32] = match txid.try_into() {
        Ok(arr) => arr,
        Err(_) => panic!("Expected a Vec of length 32, but it was {}", tx.len()),
    };

    tx_array
}

pub fn collect_txids(tx: Transaction) -> String {
    let mut input_vecs: Vec<Vec<u8>> = Vec::new();
    let mut output_vecs: Vec<Vec<u8>> = Vec::new();

    for ins in tx.vin {
        let mut input: Vec<u8> = Vec::new();

        // add outpoint
        let txid = hex::decode(ins.txid).unwrap();
        let reversed_txid: Vec<u8> = txid.iter().rev().cloned().collect();
        input.extend_from_slice(&reversed_txid);
        input.extend_from_slice(&ins.vout.to_le_bytes());

        // add scriptSig
        let scriptSig = hex::decode(ins.scriptsig).unwrap();
        let scriptSig_size = scriptSig.len() as u64;
        let scriptsig_size_in_varint = turn_to_varint(scriptSig_size);
        input.extend_from_slice(&scriptsig_size_in_varint);
        input.extend_from_slice(&scriptSig);

        // add sequence
        input.extend_from_slice(&ins.sequence.to_le_bytes());

        input_vecs.push(input);
    }

    for outs in tx.vout {
        let mut output: Vec<u8> = Vec::new();

        // add value
        let value = outs.value.to_le_bytes();
        output.extend_from_slice(&value);

        // add scriptPubKey
        let scriptPubKey = hex::decode(outs.scriptpubkey).unwrap();
        let scriptPubKey_size = scriptPubKey.len() as u64;
        let scriptPubKey_size_in_varint = turn_to_varint(scriptPubKey_size);
        output.extend_from_slice(&scriptPubKey_size_in_varint);
        output.extend_from_slice(&scriptPubKey);

        output_vecs.push(output);
    }

    let txid = get_txid(tx.version, input_vecs, output_vecs, tx.locktime);
    let reversed_txid: Vec<u8> = txid.iter().rev().cloned().collect();
    let txid_in_string = hex::encode(reversed_txid);

    txid_in_string
}

fn turn_to_varint(num: u64) -> Vec<u8> {
    let mut varint = Vec::new();
    if num < 0xfd {
        varint.push(num as u8);
    } else if num <= 0xffff {
        varint.push(0xfd);
        varint.extend_from_slice(&(num as u16).to_le_bytes());
    } else if num <= 0xffffffff {
        varint.push(0xfe);
        varint.extend_from_slice(&(num as u32).to_le_bytes());
    } else {
        varint.push(0xff);
        varint.extend_from_slice(&num.to_le_bytes());
    }
    varint
}

fn get_commitment_hash_segwit(
    tx: Transaction,
    version: u32,
    sighash_type: u32,
    locktime: u32,
    scriptcode: Vec<u8>,
    sequence: u32,
    spent: u64,
    outpoint_txid: String,
    outpoint_vout: u32,
) -> Vec<u8> {
    let mut commitment = Vec::new();

    //version
    commitment.extend_from_slice(&version.to_le_bytes());

    //hashprevouts
    let mut temp: Vec<u8> = Vec::new();

    for ins in &tx.vin {
        // add txid
        let txid_in_bytes = hex::decode(ins.txid.clone()).unwrap();
        let mut txid_reversed = txid_in_bytes;
        txid_reversed.reverse();
        temp.extend_from_slice(&txid_reversed);

        // add vout
        temp.extend_from_slice(&ins.vout.to_le_bytes());
    }

    let hashprevouts = sha256_hash(&sha256_hash(&temp));
    commitment.extend_from_slice(&hashprevouts);

    //hashsequence
    let mut temp2: Vec<u8> = Vec::new();

    for ins in &tx.vin {
        temp2.extend_from_slice(&ins.sequence.clone().to_le_bytes());
    }

    let hashsequence = sha256_hash(&sha256_hash(&temp2));
    commitment.extend_from_slice(&hashsequence);

    //outpoint
    let out_txid = hex::decode(outpoint_txid).unwrap();
    let reversed_out_txid: Vec<u8> = out_txid.iter().rev().cloned().collect();
    commitment.extend_from_slice(&reversed_out_txid);
    commitment.extend_from_slice(&outpoint_vout.to_le_bytes());

    //scriptcode
    commitment.extend_from_slice(&scriptcode);

    //value of the output spent by the input
    commitment.extend_from_slice(&spent.to_le_bytes());

    //nsequence
    commitment.extend_from_slice(&sequence.to_le_bytes());

    //hashoutputs
    let mut temp3: Vec<u8> = Vec::new();

    for outs in tx.vout {
        temp3.extend_from_slice(&outs.value.to_le_bytes());

        // txid
        let scriptpubkey = hex::decode(&outs.scriptpubkey).unwrap();
        let len_in_varint = turn_to_varint(scriptpubkey.len() as u64);
        temp3.extend_from_slice(&len_in_varint);
        temp3.extend_from_slice(&scriptpubkey);
    }

    //temp3 as string
    let temp3_string = hex::encode(temp3.clone());

    let temp3_hash = sha256_hash(&sha256_hash(&temp3));
    commitment.extend_from_slice(&temp3_hash);

    //locktime
    commitment.extend_from_slice(&locktime.to_le_bytes());

    //sighash type
    commitment.extend_from_slice(&sighash_type.to_le_bytes());

    //double sha256 hash of the serialized commitment
    return sha256_hash(&sha256_hash(&commitment));

    //OK
}

fn get_commitment_hash_legacy(
    version: u32,
    tx: Transaction,
    index: u32,
    sighash_type: u32,
) -> Vec<u8> {
    let mut commitment = Vec::new();

    //version
    commitment.extend_from_slice(&version.to_le_bytes());

    //input length
    let ip_len = tx.vin.clone().len() as u64;
    let ip_len = turn_to_varint(ip_len);
    commitment.extend_from_slice(&ip_len);

    // inputs
    for (counter, ins) in tx.vin.clone().iter().enumerate() {
        if counter as u32 == index {
            // indexing staarts from zero

            // txid
            let txid_str = &ins.txid;
            let mut txid_in_bytes = hex::decode(txid_str).unwrap();
            txid_in_bytes.reverse();
            commitment.extend_from_slice(&txid_in_bytes);

            //vout
            let vout = ins.vout;
            commitment.extend_from_slice(&vout.to_le_bytes());

            // scriptpubkey length
            let scriptpubkey = hex::decode(&ins.prevout.scriptpubkey).unwrap();
            let scriptpubkey_len = scriptpubkey.len() as u64;
            let scriptpubkey_len = turn_to_varint(scriptpubkey_len);
            commitment.extend_from_slice(&scriptpubkey_len);
            commitment.extend_from_slice(&scriptpubkey);

            //sequence
            let sequence = ins.sequence;
            commitment.extend_from_slice(&sequence.to_le_bytes());
        } else {
            // txid
            let txid_str = &ins.txid;
            let mut txid_in_bytes = hex::decode(txid_str).unwrap();
            txid_in_bytes.reverse();
            commitment.extend_from_slice(&txid_in_bytes);

            //vout
            let vout = ins.vout;
            commitment.extend_from_slice(&vout.to_le_bytes());

            // scriptSig length
            commitment.push(0x00);

            //sequence
            let sequence = ins.sequence;
            commitment.extend_from_slice(&sequence.to_le_bytes());
        }
    }

    // output length
    let op_len = tx.vout.clone().len() as u64;
    let op_len = turn_to_varint(op_len);
    commitment.extend_from_slice(&op_len);

    // outputs

    for outs in tx.vout.clone() {
        // value
        let value = outs.value;
        commitment.extend_from_slice(&value.to_le_bytes());

        // scriptpubkey length
        let scriptpubkey = hex::decode(&outs.scriptpubkey).unwrap();
        let scriptpubkey_len = scriptpubkey.len() as u64;
        let scriptpubkey_len = turn_to_varint(scriptpubkey_len);
        commitment.extend_from_slice(&scriptpubkey_len);
        commitment.extend_from_slice(&scriptpubkey);
    }

    //locktime
    let locktime = tx.locktime;
    commitment.extend_from_slice(&locktime.to_le_bytes());

    //sighash type
    commitment.extend_from_slice(&sighash_type.to_le_bytes());

    let commitment_hash = sha256_hash(&sha256_hash(&commitment));

    commitment_hash
}

pub fn test_weight(tx: Transaction) -> u64 {
    let mut input_vecs: Vec<Vec<u8>> = Vec::new();
    let mut output_vecs: Vec<Vec<u8>> = Vec::new();
    let mut witness_vecs: Vec<Vec<u8>> = Vec::new();

    for ins in tx.vin.clone() {
        let mut input: Vec<u8> = Vec::new();

        // add outpoint
        let txid = hex::decode(ins.txid).unwrap();
        let reversed_txid: Vec<u8> = txid.iter().rev().cloned().collect();
        input.extend_from_slice(&reversed_txid);
        input.extend_from_slice(&ins.vout.to_le_bytes());

        // add scriptSig
        let scriptSig = hex::decode(ins.scriptsig).unwrap();
        let scriptSig_size = scriptSig.len() as u64;
        let scriptsig_size_in_varint = turn_to_varint(scriptSig_size);
        input.extend_from_slice(&scriptsig_size_in_varint);
        input.extend_from_slice(&scriptSig);

        // add sequence
        input.extend_from_slice(&ins.sequence.to_le_bytes());

        input_vecs.push(input);
    }

    for outs in tx.vout.clone() {
        let mut output: Vec<u8> = Vec::new();

        // add value
        let value = outs.value.to_le_bytes();
        output.extend_from_slice(&value);

        // add scriptPubKey
        let scriptPubKey = hex::decode(outs.scriptpubkey).unwrap();
        let scriptPubKey_size = scriptPubKey.len() as u64;
        let scriptPubKey_size_in_varint = turn_to_varint(scriptPubKey_size);
        output.extend_from_slice(&scriptPubKey_size_in_varint);
        output.extend_from_slice(&scriptPubKey);

        output_vecs.push(output);
    }

    for ins in tx.vin.clone() {
        let mut witness_vec: Vec<u8> = Vec::new();

        if let Some(witness) = ins.witness {
            let witness_len = witness.len() as u64;
            let witness_len_in_varint = turn_to_varint(witness_len);
            witness_vec.extend_from_slice(&witness_len_in_varint);

            for x in witness {
                let witness_in_bytes = hex::decode(x).unwrap();
                let witness_size = witness_in_bytes.len() as u64;
                let witness_size_in_varint = turn_to_varint(witness_size);
                witness_vec.extend_from_slice(&witness_size_in_varint);
                witness_vec.extend_from_slice(&witness_in_bytes);
            }
        }

        witness_vecs.push(witness_vec);
    }

    let (witness_data, non_witness_data) =
        divide_and_conquer(tx.clone(), input_vecs, output_vecs, witness_vecs);

    let new_wt = correct_cal_weight(non_witness_data, witness_data);
    new_wt
}

fn divide_and_conquer(
    tx: Transaction,
    inputs: Vec<Vec<u8>>,
    outputs: Vec<Vec<u8>>,
    witnesses: Vec<Vec<u8>>,
) -> (Vec<u8>, Vec<u8>) {
    let mut witness_data: Vec<u8> = Vec::new();
    let mut non_witness_data: Vec<u8> = Vec::new();

    //version
    non_witness_data.extend_from_slice(&tx.version.to_le_bytes());

    let flag: u16 = 0x0001;
    witness_data.extend_from_slice(&flag.to_be_bytes());

    //number of inputs
    let number_of_inputs = inputs.len() as u64;
    let varint_bytes = turn_to_varint(number_of_inputs);
    non_witness_data.extend_from_slice(&varint_bytes);

    //inputs
    //assuming that I am already giving the inputs in the correct serialised format
    for input in inputs {
        non_witness_data.extend_from_slice(&input);
    }

    //number of outputs
    let number_of_outputs = outputs.len() as u64;
    let varint_bytes = turn_to_varint(number_of_outputs);
    non_witness_data.extend_from_slice(&varint_bytes);

    //outputs
    for output in outputs {
        non_witness_data.extend_from_slice(&output);
    }

    //witnesses
    //assuming witnesses are already in the correct format
    for witness in witnesses {
        witness_data.extend_from_slice(&witness);
    }

    //locktime
    non_witness_data.extend_from_slice(&tx.locktime.to_le_bytes()); // locktime

    (witness_data, non_witness_data)
}

#[cfg(test)]
#[test]
fn test_script() {
    let mut data: Vec<u8> = Vec::new();
    let scriptsig = "";
    let scriptsig = hex::decode(scriptsig).unwrap();
    let scriptsig_length = scriptsig.len() as u8;

    data.push(scriptsig_length);
    data.extend_from_slice(&scriptsig);

    assert_eq!(data, [0x00]);
}

// #[test]
// fn test_merkle_() {
//     let txns = vec![
//         "3bd3a1309a518c381248fdc26c3a6bd62c35db7705069f59206684308cc237b3".to_string(),
//         "a99011a19e9894753d6c65c8fa412838ea8042886537588e7205734d5de8956d".to_string(),
//     ];
//     let merkle_root = get_merkle_root(txns);
//     let merkle_root_in_hex = hex::encode(merkle_root);

//     assert_eq!(
//         merkle_root_in_hex,
//         "25c8487847de572c21bff029a95d9a9fecd9f4c2736984b979d37258cd47bd1f"
//     );
// }

// #[test]
// fn test_merkle_2() {
//     let txns = vec![
//         "e72a45e7ca5618abe201d842faf0bf3a2933728ea52396b32c5c6f0c5256b583".to_string(),
//         "c834a9e951cf736f11191522477929813855153c6fd6bf1bc818843ad40c6633".to_string(),
//         "40a84ee492436c3bcaa139b2e9fb5c423bbe2b9db693723a885d46ab5a48d564".to_string(),
//     ];
//     let merkle_root = get_merkle_root(txns);
//     let merkle_root_in_hex = hex::encode(merkle_root);

//     assert_eq!(
//         merkle_root_in_hex,
//         "1c66ef9ddd32c82f34c46957dbdbb47c82b65339ef6cd4c887f4439a6c1bcfb8"
//     );
// }

#[test]
fn test_get_r_s() {
    let sign_as_witness : String = "304402207ed00dfbbf904a6f24d43725fe3cd9d8fec2f5b6f6a7ac7b1e0816e39266ff7602200966bdee875f64538a655dd2a0bc548c3deb5fd717ec3e9e107d1233533cc23a01".to_string();

    //remove sighash type from signature
    let sign_in_hex : String = "304402207ed00dfbbf904a6f24d43725fe3cd9d8fec2f5b6f6a7ac7b1e0816e39266ff7602200966bdee875f64538a655dd2a0bc548c3deb5fd717ec3e9e107d1233533cc23a".to_string();

    let sign_in_bytes = hex::decode(sign_in_hex).unwrap();

    let sign = Signature::parse_der(&sign_in_bytes).unwrap();
    let r = sign.r.b32();
    let s = sign.s.b32();

    let r_in_hex = hex::encode(r);
    let s_in_hex = hex::encode(s);

    assert_eq!(
        r_in_hex,
        "7ed00dfbbf904a6f24d43725fe3cd9d8fec2f5b6f6a7ac7b1e0816e39266ff76"
    );
    assert_eq!(
        s_in_hex,
        "0966bdee875f64538a655dd2a0bc548c3deb5fd717ec3e9e107d1233533cc23a"
    );
}

#[test]
fn test_signature_verification() {
    let sign = "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee";
    let sign_in_bytes = hex::decode(sign).unwrap();
    let signature = Signature::parse_der(&sign_in_bytes).unwrap();

    let pubkey = "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357";
    let pubkey_in_bytes: Vec<u8> = hex::decode(pubkey).unwrap();
    let pubkey_in_bytes: [u8; 33] = pubkey_in_bytes.try_into().unwrap();
    let pubkey = PublicKey::parse_compressed(&pubkey_in_bytes).unwrap();

    let msg_hash = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670";
    let msg_hash_in_bytes = hex::decode(msg_hash).unwrap();
    let commit_msg = Message::parse_slice(&msg_hash_in_bytes).unwrap();

    let ret = verify(&commit_msg, &signature, &pubkey);
    assert_eq!(ret, true);
}

#[test]
fn test_p2wpkh() {
    for entry in fs::read_dir("../mempool_test").unwrap() {
        let tx: Transaction =
            serde_json::from_str(&fs::read_to_string(entry.unwrap().path()).unwrap()).unwrap();

        let tx_clone = tx.clone();

        for (counter, ins) in tx_clone.vin.iter().enumerate() {
            let sign_in_witness = ins.witness.clone().unwrap()[0].clone();
            let sign_to_bytes = hex::decode(sign_in_witness).unwrap();

            let sign_to_verify = &sign_to_bytes[..sign_to_bytes.len() - 1];

            let pubkey = ins.witness.clone().unwrap()[1].clone();
            let pubkey_in_bytes_vec = hex::decode(pubkey).unwrap();
            let pubkey_in_bytes: [u8; 33] = pubkey_in_bytes_vec.clone().try_into().unwrap();

            // extract last byte of the sign
            let sighash = sign_to_bytes.last().cloned().unwrap();

            //scriptcode 0x1976a914{20-byte-pubkey-hash}88ac
            let mut scriptcode: Vec<u8> = Vec::new();
            scriptcode.push(0x19);
            scriptcode.push(0x76);
            scriptcode.push(0xa9);
            scriptcode.push(0x14);
            let pub_hash = hash160(&pubkey_in_bytes_vec);
            scriptcode.extend_from_slice(&pub_hash);
            scriptcode.push(0x88);
            scriptcode.push(0xac);

            let hash = get_commitment_hash_segwit(
                tx.clone(),
                tx.version,
                sighash as u32,
                tx.locktime,
                scriptcode,
                ins.sequence,
                ins.prevout.value,
                ins.txid.clone(),
                ins.vout,
            );

            // verification
            let signature = Signature::parse_der(&sign_to_verify).unwrap();
            let pubkey = PublicKey::parse_compressed(&pubkey_in_bytes).unwrap();
            let msg = Message::parse_slice(&hash).unwrap();

            let ret = verify(&msg, &signature, &pubkey);
            assert_eq!(ret, true);
        }
    }
}

#[test]
fn test_p2wsh() {
    for entry in fs::read_dir("../mempool_p2wsh").unwrap() {
        let tx: Transaction =
            serde_json::from_str(&fs::read_to_string(entry.unwrap().path()).unwrap()).unwrap();

        let tx_clone = tx.clone();

        for (counter, ins) in tx_clone.vin.iter().enumerate() {
            let witness_len = ins.witness.clone().unwrap().len();

            let mut signatures_vector: Vec<Vec<u8>> = Vec::new();
            let mut sighash_vector: HashMap<Vec<u8>, u32> = HashMap::new();
            let mut pubkey_vec: Vec<[u8; 33]> = Vec::new();
            let mut pubkey_hash_vec: Vec<Vec<u8>> = Vec::new();

            for i in 0..(witness_len - 1) {
                let witness_to_bytes =
                    hex::decode(ins.witness.clone().unwrap()[i].clone()).unwrap();

                if witness_to_bytes.len() == 0 {
                    continue;
                }

                let sign_to_verify = witness_to_bytes[..witness_to_bytes.len() - 1].to_vec();
                let sighash = witness_to_bytes.last().cloned().unwrap();

                signatures_vector.push(sign_to_verify.clone());
                sighash_vector.insert(sign_to_verify, sighash as u32);
            }

            let mut pubkey_vec_in_string = ins.witness.clone().unwrap()[witness_len - 1].clone();

            let number_sign_req = pubkey_vec_in_string[0..2].to_string();
            let number_sign_req = u32::from_str_radix(&number_sign_req, 16).unwrap() - 0x50;

            for i in 0..(witness_len - 1) {
                if i == 0 {
                    // Remove first byte from the pubkey_vec_in_string
                    pubkey_vec_in_string = pubkey_vec_in_string[2..].to_string();
                }

                // Take the first 34 bytes
                let first_34_bytes = &pubkey_vec_in_string[..68];

                //remove first byte from this
                let first_33_bytes = &first_34_bytes[2..];

                //convert to bytes and push in pubkey vector
                let pubkey_in_bytes_vec = hex::decode(first_33_bytes).unwrap();
                let pubkey_in_bytes: [u8; 33] = pubkey_in_bytes_vec.clone().try_into().unwrap();
                pubkey_vec.push(pubkey_in_bytes);

                // Now remove this 34 bytes and update the pubkey_vec_in_string
                pubkey_vec_in_string = pubkey_vec_in_string[68..].to_string();
            }

            for pubkey in pubkey_vec.clone() {
                //pubkey in string
                let pubkey_in_string = hex::encode(pubkey.clone());

                pubkey_hash_vec.push(sha256_hash(&pubkey.clone()));
            }

            let mut total_ok: u32 = 0;

            for sig in signatures_vector {
                let sign = Signature::parse_der(&sig).unwrap();

                for (counter, pubkey) in pubkey_vec.iter().enumerate() {
                    let pubkey_hash = pubkey_hash_vec[counter].clone();

                    let mut scriptcode: Vec<u8> = Vec::new();
                    let redeem_script_str = ins.witness.clone().unwrap()[witness_len - 1].clone();
                    let rs_vec = hex::decode(redeem_script_str).unwrap();
                    let rs_size = rs_vec.len() as u64;
                    let rs_size_in_varint = turn_to_varint(rs_size);
                    scriptcode.extend_from_slice(&rs_size_in_varint);
                    scriptcode.extend_from_slice(&rs_vec);

                    let hash = get_commitment_hash_segwit(
                        tx.clone(),
                        tx.version,
                        sighash_vector[&sig.clone()],
                        tx.locktime,
                        scriptcode,
                        ins.sequence,
                        ins.prevout.value,
                        ins.txid.clone(),
                        ins.vout,
                    );

                    let pubkey = PublicKey::parse_compressed(&pubkey).unwrap();
                    let msg = Message::parse_slice(&hash).unwrap();

                    let ret = verify(&msg, &sign, &pubkey);
                    if ret {
                        total_ok = total_ok + 1;
                    }
                }
            }

            assert_eq!(total_ok >= number_sign_req as u32, true);
        }
    }
}

#[test]
fn test_p2pkh() {
    for entry in fs::read_dir("../mempool_p2pkh").unwrap() {
        let tx: Transaction =
            serde_json::from_str(&fs::read_to_string(entry.unwrap().path()).unwrap()).unwrap();

        for ins in tx.vin.clone() {
            let sig_len_hex = &ins.scriptsig[..2];
            let sig_len_bytes = hex::decode(sig_len_hex).unwrap();
            let convert_to_dec = u8::from_be_bytes(sig_len_bytes.try_into().unwrap()) as usize;

            // Take convert_to_dec bytes (2*convert_to_dec characters) after the first byte
            let sig_w_sighash = &ins.scriptsig[2..(2 + 2 * convert_to_dec)];
            let sighash = &sig_w_sighash.clone()[(2 * convert_to_dec - 2)..];
            let sighash = u8::from_str_radix(sighash, 16).unwrap();
            let sig = &sig_w_sighash.clone()[..(2 * convert_to_dec - 2)];

            // Take the rest of the string
            let pubkey_str = &ins.scriptsig[((2 + 2 * convert_to_dec) + 2)..];
            let pubkey_in_bytes: Vec<u8> = hex::decode(pubkey_str).unwrap();
            let pubkey_in_bytes: [u8; 33] = pubkey_in_bytes.try_into().unwrap();
            let pubkey = PublicKey::parse_compressed(&pubkey_in_bytes.clone()).unwrap();

            let sig_in_bytes = hex::decode(sig).unwrap();
            let sign = Signature::parse_der(&sig_in_bytes).unwrap();

            let hash = get_commitment_hash_legacy(
                tx.clone().version,
                tx.clone(),
                0, // index of the input , do this with a counter
                sighash as u32,
            );

            let msg = Message::parse_slice(&hash).unwrap();

            let ret = verify(&msg, &sign, &pubkey);

            assert_eq!(ret, true);
        }
    }
}

#[test]
fn test_p2sh_p2wpkh() {
    for entry in fs::read_dir("../mempool_p2sh_p2wpkh").unwrap() {
        let tx: Transaction =
            serde_json::from_str(&fs::read_to_string(entry.unwrap().path()).unwrap()).unwrap();

        for ins in tx.vin.clone() {
            let sign_in_witness = ins.witness.clone().unwrap()[0].clone();
            let sign_to_bytes = hex::decode(sign_in_witness).unwrap();

            let sign_to_verify = &sign_to_bytes[..sign_to_bytes.len() - 1];

            let pubkey = ins.witness.clone().unwrap()[1].clone();
            let pubkey_in_bytes_vec = hex::decode(pubkey).unwrap();
            let pubkey_in_bytes: [u8; 33] = pubkey_in_bytes_vec.clone().try_into().unwrap();

            // extract last byte of the sign
            let sighash = sign_to_bytes.last().cloned().unwrap();

            let mut scriptcode: Vec<u8> = Vec::new();
            scriptcode.push(0x19);
            scriptcode.push(0x76);
            scriptcode.push(0xa9);
            scriptcode.push(0x14);
            let pub_hash = hash160(&pubkey_in_bytes_vec);
            scriptcode.extend_from_slice(&pub_hash);
            scriptcode.push(0x88);
            scriptcode.push(0xac);

            let hash = get_commitment_hash_segwit(
                tx.clone(),
                tx.version,
                sighash as u32,
                tx.locktime,
                scriptcode,
                ins.sequence,
                ins.prevout.value,
                ins.txid.clone(),
                ins.vout,
            );

            // verification
            let signature = Signature::parse_der(&sign_to_verify).unwrap();
            let pubkey = PublicKey::parse_compressed(&pubkey_in_bytes).unwrap();
            let msg = Message::parse_slice(&hash).unwrap();

            let ret = verify(&msg, &signature, &pubkey);
            assert_eq!(ret, true);
        }
    }
}

#[test]
fn test_p2sh_p2wsh() {
    for entry in fs::read_dir("../mempool_p2sh_p2wsh").unwrap() {
        let tx: Transaction =
            serde_json::from_str(&fs::read_to_string(entry.unwrap().path()).unwrap()).unwrap();

        for ins in tx.vin.clone() {
            let witness_len = ins.witness.clone().unwrap().len();

            let mut signatures_vector: Vec<Vec<u8>> = Vec::new();
            let mut sighash_vector: HashMap<Vec<u8>, u32> = HashMap::new();
            let mut pubkey_vec: Vec<[u8; 33]> = Vec::new();
            let mut pubkey_hash_vec: Vec<Vec<u8>> = Vec::new();

            for i in 0..(witness_len - 1) {
                let witness_to_bytes =
                    hex::decode(ins.witness.clone().unwrap()[i].clone()).unwrap();

                if witness_to_bytes.len() == 0 {
                    continue;
                }

                let sign_to_verify = witness_to_bytes[..witness_to_bytes.len() - 1].to_vec();
                let sighash = witness_to_bytes.last().cloned().unwrap();

                signatures_vector.push(sign_to_verify.clone());
                sighash_vector.insert(sign_to_verify, sighash as u32);
            }

            let mut pubkey_vec_in_string = ins.witness.clone().unwrap()[witness_len - 1].clone();

            let number_sign_req = pubkey_vec_in_string[0..2].to_string();
            let number_sign_req = u32::from_str_radix(&number_sign_req, 16).unwrap() - 0x50;

            for i in 0..(witness_len - 1) {
                if i == 0 {
                    // Remove first byte from the pubkey_vec_in_string
                    pubkey_vec_in_string = pubkey_vec_in_string[2..].to_string();
                }

                // Take the first 34 bytes
                let first_34_bytes = &pubkey_vec_in_string[..68];

                //remove first byte from this
                let first_33_bytes = &first_34_bytes[2..];

                //convert to bytes and push in pubkey vector
                let pubkey_in_bytes_vec = hex::decode(first_33_bytes).unwrap();
                let pubkey_in_bytes: [u8; 33] = pubkey_in_bytes_vec.clone().try_into().unwrap();
                pubkey_vec.push(pubkey_in_bytes);

                // Now remove this 34 bytes and update the pubkey_vec_in_string
                pubkey_vec_in_string = pubkey_vec_in_string[68..].to_string();
            }

            for pubkey in pubkey_vec.clone() {
                pubkey_hash_vec.push(sha256_hash(&pubkey.clone()));
            }

            let mut total_ok: u32 = 0;

            let mut scriptcode: Vec<u8> = Vec::new();
            let redeem_script_str = ins.witness.clone().unwrap()[witness_len - 1].clone();
            let rs_vec = hex::decode(redeem_script_str).unwrap();
            let rs_size = rs_vec.len() as u64;
            let rs_size_in_varint = turn_to_varint(rs_size);
            scriptcode.extend_from_slice(&rs_size_in_varint);
            scriptcode.extend_from_slice(&rs_vec);

            for sig in signatures_vector {
                let sign = Signature::parse_der(&sig).unwrap();

                for (counter, pubkey) in pubkey_vec.iter().enumerate() {
                    let pubkey_hash = pubkey_hash_vec[counter].clone();

                    let hash = get_commitment_hash_segwit(
                        tx.clone(),
                        tx.version,
                        sighash_vector[&sig.clone()],
                        tx.locktime,
                        scriptcode.clone(),
                        ins.sequence,
                        ins.prevout.value,
                        ins.txid.clone(),
                        ins.vout,
                    );

                    let pubkey = PublicKey::parse_compressed(&pubkey).unwrap();
                    let msg = Message::parse_slice(&hash).unwrap();

                    let ret = verify(&msg, &sign, &pubkey);
                    if ret {
                        total_ok = total_ok + 1;
                    }
                }
            }

            assert_eq!(total_ok >= number_sign_req as u32, true);
        }
    }
}

#[test]
fn test_pure_p2sh() {
    for entry in fs::read_dir("../mempool_pure_p2sh").unwrap() {
        let tx: Transaction =
            serde_json::from_str(&fs::read_to_string(entry.unwrap().path()).unwrap()).unwrap();

        for (counter, ins) in tx.vin.clone().iter().enumerate() {
            let mut start = 2; // Skip the first two characters (OP_0 opcode)

            let bytes_per_signature = 72 * 2; // 72 bytes, each byte represented by 2 hexadecimal characters

            let mut signatures = Vec::new();

            // Extract signatures
            while &ins.scriptsig[start..start + 2] == "48" {
                let sig_end = start + 2 + bytes_per_signature;
                let sig = &ins.scriptsig[start + 2..sig_end];
                signatures.push(sig);
                start = sig_end; // No need to skip any characters here
            }

            let redeem_script = &ins.scriptsig[start..];
            let redeem_script = &redeem_script[4..];

            // Extract redeem script
            let parts: Vec<&str> = ins
                .inner_redeemscript_asm
                .as_ref()
                .unwrap()
                .split(' ')
                .collect();

            let mut public_keys: Vec<[u8; 33]> = Vec::new();

            for i in 0..parts.len() {
                if parts[i].starts_with("OP_PUSHBYTES_33") && i + 1 < parts.len() {
                    let bytes = hex::decode(parts[i + 1]).expect("Failed to decode hex");
                    let array: [u8; 33] =
                        bytes.try_into().expect("Failed to convert into byte array");
                    public_keys.push(array);
                }
            }

            let mut total_ok: u32 = 0;
            let signs_required = &parts[0][parts[0].len() - 1..];

            let signs_req: u32 = signs_required
                .parse()
                .expect("Failed to parse number of required signatures");

            for signs in signatures {
                let sign_to_bytes = hex::decode(signs).unwrap();
                let sign_to_verify = &sign_to_bytes[..sign_to_bytes.len() - 1];
                let sighash = sign_to_bytes.last().cloned().unwrap();

                for pubkey in public_keys.clone() {
                    let hash = get_commitment_hash_legacy(
                        tx.clone().version,
                        tx.clone(),
                        counter as u32, // index of the input , do this with a counter
                        sighash as u32,
                    );

                    let pubkey = PublicKey::parse_compressed(&pubkey);
                    let msg = Message::parse_slice(&hash).unwrap();
                    let sign = Signature::parse_der(&sign_to_verify).unwrap();

                    let ret = verify(&msg, &sign, &pubkey.unwrap());

                    if ret {
                        total_ok = total_ok + 1;
                    }
                }
            }

            assert_eq!(total_ok >= signs_req, true);
        }
    }
}

fn assemble_transaction(
    version: u32,
    inputs: Vec<Vec<u8>>,
    outputs: Vec<Vec<u8>>,
    witnesses: Vec<Vec<u8>>,
    locktime: u32,
) -> Vec<u8> {
    let mut assembledtransaction = Vec::new();

    assembledtransaction.extend_from_slice(&version.to_le_bytes()); // version

    // flag
    let flag: u16 = 0x0001;
    assembledtransaction.extend_from_slice(&flag.to_be_bytes()); // flag

    //number of inputs
    let number_of_inputs = inputs.len() as u64;
    let varint_bytes = turn_to_varint(number_of_inputs);
    assembledtransaction.extend_from_slice(&varint_bytes);

    //inputs
    //assuming that I am already giving the inputs in the correct serialised format
    for input in inputs {
        assembledtransaction.extend_from_slice(&input);
    }

    //number of outputs
    let number_of_outputs = outputs.len() as u64;
    let varint_bytes = turn_to_varint(number_of_outputs);
    assembledtransaction.extend_from_slice(&varint_bytes);

    //outputs
    for output in outputs {
        assembledtransaction.extend_from_slice(&output);
    }

    //witnesses
    //assuming witnesses are already in the correct format
    for witness in witnesses {
        assembledtransaction.extend_from_slice(&witness);
    }

    //locktime
    assembledtransaction.extend_from_slice(&locktime.to_le_bytes()); // locktime

    assembledtransaction

    //Ok
}

fn compress_pubkey(pubkey: &[u8]) -> Vec<u8> {
    let pubkey = PublicKey::parse_slice(pubkey, None).expect("Invalid public key");
    let serialized = pubkey.serialize_compressed();
    serialized.to_vec()
}

fn get_merkle_root_wtxid(wtxids: &[Vec<u8>]) -> Vec<u8> {
    // Convert wtxids to Vec<String>
    let wtxids_str = wtxids
        .iter()
        .map(|wtxid| hex::encode(wtxid))
        .collect::<Vec<_>>();

    // Call get_merkle_root
    let merkle_root = get_merkle_root(wtxids_str);

    // Convert [u8; 32] to Vec<u8>
    let merkle_root_vec = merkle_root.to_vec();

    merkle_root_vec
}

fn get_wtxid(tx: Transaction) -> Vec<u8> {
    let mut input_vecs: Vec<Vec<u8>> = Vec::new();
    let mut output_vecs: Vec<Vec<u8>> = Vec::new();
    let mut witness_vecs: Vec<Vec<u8>> = Vec::new();

    let mut total: u32 = 0;
    let mut non_segwit: u32 = 0;

    for ins in tx.vin.clone() {
        let mut input: Vec<u8> = Vec::new();

        total = total + 1;

        if ins.prevout.scriptpubkey_type == "p2pkh" {
            non_segwit = non_segwit + 1;
        }

        // add outpoint
        let txid = hex::decode(ins.txid).unwrap();
        let reversed_txid: Vec<u8> = txid.iter().rev().cloned().collect();
        input.extend_from_slice(&reversed_txid);
        input.extend_from_slice(&ins.vout.to_le_bytes());

        // add scriptSig
        let scriptSig = hex::decode(ins.scriptsig).unwrap();
        let scriptSig_size = scriptSig.len() as u64;
        let scriptsig_size_in_varint = turn_to_varint(scriptSig_size);
        input.extend_from_slice(&scriptsig_size_in_varint);
        input.extend_from_slice(&scriptSig);

        // add sequence
        input.extend_from_slice(&ins.sequence.to_le_bytes());

        input_vecs.push(input);
    }

    for outs in tx.vout.clone() {
        let mut output: Vec<u8> = Vec::new();

        // add value
        let value = outs.value.to_le_bytes();
        output.extend_from_slice(&value);

        // add scriptPubKey
        let scriptPubKey = hex::decode(outs.scriptpubkey).unwrap();
        let scriptPubKey_size = scriptPubKey.len() as u64;
        let scriptPubKey_size_in_varint = turn_to_varint(scriptPubKey_size);
        output.extend_from_slice(&scriptPubKey_size_in_varint);
        output.extend_from_slice(&scriptPubKey);

        output_vecs.push(output);
    }

    if total == non_segwit {
        let txid = get_txid(tx.version, input_vecs, output_vecs, tx.locktime);
        return txid.to_vec().iter().rev().cloned().collect();
    }

    for ins in tx.vin.clone() {
        let mut witness_vec: Vec<u8> = Vec::new();

        if let Some(witness) = ins.witness.clone() {
            let witness_len = witness.len() as u64;
            let witness_len_in_varint = turn_to_varint(witness_len);
            witness_vec.extend_from_slice(&witness_len_in_varint);

            for x in witness {
                let witness_in_bytes = hex::decode(x).unwrap();
                let witness_size = witness_in_bytes.len() as u64;
                let witness_size_in_varint = turn_to_varint(witness_size);
                witness_vec.extend_from_slice(&witness_size_in_varint);
                witness_vec.extend_from_slice(&witness_in_bytes);
            }
        } else {
            witness_vec.push(0x00);
        }
        witness_vecs.push(witness_vec);
    }

    let serialised = assemble_transaction(
        tx.version,
        input_vecs,
        output_vecs,
        witness_vecs,
        tx.locktime,
    );

    let wtxid = sha256_hash(&sha256_hash(&serialised));

    // reversed
    let reversed_txid = wtxid.iter().rev().cloned().collect();
    // wtxid
    reversed_txid

    // serialised
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_merkle_root() {
        let wtxids = vec![
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            "8700d546b39e1a0faf34c98067356206db50fdef24e2f70b431006c59d548ea2".to_string(),
            "c54bab5960d3a416c40464fa67af1ddeb63a2ce60a0b3c36f11896ef26cbcb87".to_string(),
            "e51de361009ef955f182922647622f9662d1a77ca87c4eb2fd7996b2fe0d7785".to_string(),
        ];

        let expected_root_hash = "dbee9a868a8caa2a1ddf683af1642a88dfb7ac7ce3ecb5d043586811a41fdbf2";
        let expected_root_hash = hex::decode(expected_root_hash).unwrap();
        let expected_root_hash: [u8; 32] = match expected_root_hash.try_into() {
            Ok(arr) => arr,
            Err(_) => self::panic!("Expected a Vec of length 32"),
        };

        let computed_root_hash = get_merkle_root(wtxids);

        assert_eq!(computed_root_hash, expected_root_hash);
        let data = vec![
            176, 133, 128, 47, 233, 58, 121, 200, 3, 101, 49, 57, 195, 20, 199, 98, 163, 198, 109,
            120, 224, 168, 233, 0, 71, 202, 174, 128, 253, 37, 179, 135,
        ];
        let hex_string = hex::encode(data);
        assert_eq!(
            hex_string,
            "b085802fe93a79c803653139c314c762a3c66d78e0a8e90047caae80fd25b387"
        );
    }
}

#[test]
fn test_get_wtxid() {
    for entry in fs::read_dir("../mempool_test").unwrap() {
        let tx: Transaction =
            serde_json::from_str(&fs::read_to_string(entry.unwrap().path()).unwrap()).unwrap();

        let wtxid = get_wtxid(tx);

        let expected_wtxid = hex::encode(wtxid);
        assert_eq!( expected_wtxid , "0200000000010117829ba9d14d441742d8d3f692efb3629742d5bf239a7017e3135be0b2c27996010000000000000000012202000000000000225120ea6e164912a1bd91f6b8652826dc3fa780c93f1a789e7a8a1ff61dfdce2801560341a0b18a9af707e1548028a8e86608ec2b40055573b6dc6a6bd70a6eb9009cfa85c5160f151567f09a8f6fe4f0571135c2bf2a76aaa2ebde5d6684bd06a3f1002701fd8a0251690063036f7264010117746578742f68746d6c3b636861727365743d7574662d38004d08023c73637269707420646174612d733d2230786130313937336161653638653261613639383761323131306430336366323639383863343732663036393338303533653531373865343565626634386566643622207372633d222f636f6e74656e742f663830623933343636613238633565666337303366616230326265656262663465333265316263346630363361633237666564666437396164393832663263656930223e3c2f7363726970743e3c626f6479207374796c653d22646973706c61793a206e6f6e65223e3c2f626f64793e000000000000000062766d76341bc301f867404fd30ee425db8e71603b2d0eb7c070bec1090002971c3336bec9ab0687d9589e16c599eb2df8f4d7b67f020010f311150465150a9e16f4008209664d52fe819620492d030a414224b3f175b88af0b71b6b73a7b5eb773d80660985578b86270197ae295a847d506d5d01b819eb2730c6010b0932ca4c46a200a77da942914fb6ef426400d4d5879a245f8017212fc212dcaafa41c9f583788fc231e1fd3d21ab3113f9424b55d851125d3c585386903684a278db8185f2c5ecf1cb9c9c52ca90d763b0a1f9f5347310793057ecc6b9adbc3f0b61c3002dfc407ac991d98e986247edad4174dc88e2de14fd5e0b0395644181e20d833feaf8a4b228da700249de6ef7b1f1bc538e8fb6bc8e33352a92df7009d850b41e726517f0abed5a1c8ceea6ff0f4c591fd5abce654cc446478658b9389ddde4497c80a9a1b6e0e6866e04f2b6ca48549b41e3d54d286b9493e22bcc63c8ee01f30f346d06db5680dc067df1f44ec6036bd3bebfbd63c47b053baa0ed9311d94cab7403d69ebd506006821c0d2d8084d959566f0788913a3b8c3a8cbf9a458d9b379839a380bd9b0aa8f57ce00000000" );
    }
}
