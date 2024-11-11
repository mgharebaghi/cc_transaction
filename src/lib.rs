//! A library for handling cryptocurrency transactions on the Centichain network.
//! 
//! This module provides functionality for creating, signing and sending transactions,
//! managing UTXOs (Unspent Transaction Outputs), and handling wallet operations.

use std::str::FromStr;

use chrono::{SubsecRound, Utc};
use reqwest::Client;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use sha2::{Digest, Sha256};
use sp_core::{
    crypto::Ss58Codec,
    ed25519::{Public, Signature},
};

/// Represents a complete transaction on the Centichain network.
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transaction {
    /// Hash of the transaction
    pub hash: String,
    /// Input details including UTXOs being spent
    pub input: Input,
    /// Output details including new unspent outputs
    pub output: Output,
    /// Transaction value
    #[serde_as(as = "DisplayFromStr")]
    pub value: Decimal,
    /// Transaction fee
    #[serde_as(as = "DisplayFromStr")]
    pub fee: Decimal,
    /// Type of transaction script (Single or Multi signature)
    pub script: Script,
    /// Transaction signatures
    pub signature: Vec<Sign>,
    /// Transaction timestamp
    pub date: String,
}

/// Represents a signature with its associated public key
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Sign {
    pub signature: Signature,
    pub key: Public,
}

/// Represents an Unspent Transaction Output (UTXO)
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UTXO {
    /// Block number where this UTXO was created
    pub block: u64,
    /// Hash of the transaction that created this UTXO
    pub trx_hash: String,
    /// Hash of the output that created this UTXO
    pub output_hash: String,
    /// Hash of the unspent amount
    pub unspent_hash: String,
    /// Unspent amount
    #[serde_as(as = "DisplayFromStr")]
    pub unspent: Decimal,
}

/// Defines the type of transaction script
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Script {
    /// Single signature required
    Single,
    /// Multiple signatures required
    Multi,
}

/// Represents the input side of a transaction
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Input {
    /// Hash of the input data
    hash: String,
    /// Number of UTXOs being spent
    number: u8,
    /// List of UTXOs being spent
    utxos: Vec<UTXO>,
}

/// Represents the output side of a transaction
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Output {
    /// Hash of the output data
    pub hash: String,
    /// Number of new unspent outputs
    pub number: usize,
    /// List of new unspent outputs
    pub unspents: Vec<Unspent>,
}

/// Represents an unspent output
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Unspent {
    /// Hash of the unspent data
    pub hash: String,
    /// Detailed unspent data
    pub data: UnspentData,
}

/// Contains the detailed data for an unspent output
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UnspentData {
    /// Recipient wallet public key
    pub wallet: Public,
    /// Random salt for hash generation
    pub salt: u32,
    /// Amount of the unspent output
    #[serde_as(as = "DisplayFromStr")]
    pub value: Decimal,
}

/// Response structure for transaction submission
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TxRes {
    /// Transaction hash
    pub hash: String,
    /// Transaction status
    pub status: String,
    /// Status description
    pub description: String,
}

/// Request body structure for UTXO queries
#[derive(Debug, Serialize, Deserialize)]
pub struct ReqBody {
    /// Wallet public key
    pub public_key: String,
    /// Type of request
    pub request: String,
    /// Transaction value
    pub value: String,
}

impl Input {
    /// Creates a new Input from a response body containing UTXO data
    fn new(response: ResBody) -> Self {
        let hash_data = serde_json::to_string(&response.utxo_data)
            .expect("Failed to serialize UTXO data");
        let hash = HashMaker::generate(&hash_data);
        Self {
            hash,
            number: response.utxo_data.len() as u8,
            utxos: response.utxo_data,
        }
    }
}

impl Output {
    /// Creates a new Output from a vector of unspent outputs
    pub fn new(unspents: Vec<Unspent>) -> Self {
        let str_outputs = serde_json::to_string(&unspents)
            .expect("Failed to serialize unspents");
        Self {
            hash: HashMaker::generate(&str_outputs),
            number: unspents.len(),
            unspents,
        }
    }
}

impl Unspent {
    /// Creates a new Unspent output for a given wallet and value
    pub fn new(wallet: &Public, value: Decimal) -> Self {
        let salt: u32 = rand::random();
        let data = UnspentData {
            wallet: *wallet,
            salt,
            value,
        };

        let hash_data = serde_json::to_string(&data)
            .expect("Failed to serialize unspent data");

        Self {
            hash: HashMaker::generate(&hash_data),
            data,
        }
    }
}

/// Handles Merkle tree operations for transaction hashing
pub struct MerkelRoot;

impl MerkelRoot {
    /// Creates a Merkle tree from a list of transaction hashes
    pub fn make(transactions: Vec<&String>) -> Vec<String> {
        let mut hashs: Vec<String> = transactions.iter().map(|t| t.to_string()).collect();

        while hashs.len() > 1 {
            let mut new_hashs = Vec::with_capacity((hashs.len() + 1) / 2);
            
            for chunk in hashs.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                if let Some(right) = chunk.get(1) {
                    hasher.update(right);
                }
                new_hashs.push(format!("{:x}", hasher.finalize()));
            }
            
            hashs = new_hashs;
        }

        hashs
    }
}

/// Utility struct for generating SHA256 hashes
pub struct HashMaker;

impl HashMaker {
    /// Generates a SHA256 hash of the input data
    pub fn generate(data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

/// Response body structure for UTXO queries
#[derive(Debug, Serialize, Deserialize)]
pub struct ResBody {
    /// Wallet public key
    pub public_key: String,
    /// List of UTXOs
    pub utxo_data: Vec<UTXO>,
    /// Response status
    pub status: String,
    /// Status description
    pub description: String,
}

impl Transaction {
    /// Sends a new transaction to the network
    pub async fn make_and_send(
        wallet: String,
        private: String,
        to: String,
        value: String,
    ) -> Result<String, String> {
        let wallet = wallet.trim();
        let decimal_value = Decimal::from_str(&value)
            .map_err(|e| format!("Invalid value format: {}", e))?;
        let fee = decimal_value * Decimal::from_str("0.01")
            .expect("Failed to parse fee percentage");

        let client = Client::new();
        let request = ReqBody {
            public_key: wallet.to_string(),
            request: "utxo".to_string(),
            value,
        };
        let req_url = "https://centichain.org/jrpc/autxo";

        let response = client
            .post(req_url)
            .json(&request)
            .send()
            .await
            .map_err(|_| "Failed to connect to server. Please check your internet connection.".to_string())?
            .json::<ResBody>()
            .await
            .map_err(|_| "Failed to parse server response".to_string())?;

        if response.status != "success" {
            return Err(response.description);
        }

        Transaction::sending(
            wallet.to_string(),
            private,
            decimal_value,
            to,
            response,
            fee,
            client,
        )
        .await
        .map(|_| "Transaction Successfully Sent".to_string())
        .map_err(|e| e.to_string())
    }

    /// Creates a new transaction with the given parameters
    async fn sending(
        public_key: String,
        private_key: String,
        value: Decimal,
        to: String,
        response: ResBody,
        fee: Decimal,
        client: Client,
    ) -> Result<(), String> {
        let wallet = sp_core::ed25519::Public::from_string(&public_key)
            .map_err(|_| "Invalid public key format")?;
        
        let sum_input: Decimal = response.utxo_data.iter()
            .map(|unspent| unspent.unspent)
            .sum();

        let input = Input::new(response);
        let to_wallet = to.parse()
            .map_err(|_| "Wallet address is incorrect")?;
        let change_wallet: Public = public_key.parse()
            .map_err(|_| "Invalid change wallet address")?;

        let mut unspents = Vec::new();
        if sum_input > value + fee {
            let change = sum_input - (value + fee);
            unspents.push(Unspent::new(&change_wallet, change));
            unspents.push(Unspent::new(&to_wallet, value));
        } else {
            unspents.push(Unspent::new(&to_wallet, value));
        }

        let output = Output::new(unspents);
        let hash = MerkelRoot::make(vec![&input.hash, &output.hash]);
        
        let sign = centichain_keypair::CentichainKey::signing(&private_key, &hash[0])
            .map_err(|_| "Failed to sign transaction")?;
        
        let signature = Sign {
            signature: sign,
            key: wallet,
        };

        let transaction = Transaction {
            hash: hash[0].clone(),
            input,
            output,
            value,
            fee,
            script: Script::Single,
            signature: vec![signature],
            date: Utc::now().round_subsecs(0).to_string(),
        };

        let raw_response = client
            .post("https://centichain.org/jrpc/trx")
            .json(&transaction)
            .send()
            .await
            .map_err(|e| format!("Failed to send transaction: {}", e))?
            .text()
            .await
            .map_err(|e| format!("Failed to get response text: {}", e))?;
        
        println!("Raw response: {}", raw_response);  // Debug line
        
        let response: TxRes = serde_json::from_str(&raw_response)
            .map_err(|e| format!("Failed to parse transaction response: {}. Raw response: {}", e, raw_response))?;

        if response.status == "success" {
            Ok(())
        } else {
            Err("Server has problem! Please try with another provider.".to_string())
        }
    }
}
