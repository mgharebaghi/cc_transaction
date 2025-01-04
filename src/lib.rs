//! A library for handling cryptocurrency transactions on the Centichain network.
//!
//! This module provides functionality for creating, signing and sending transactions,
//! managing UTXOs (Unspent Transaction Outputs), and handling wallet operations.

use std::str::FromStr;
use rand::Rng;
use reqwest::Client;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use sha2::{Digest, Sha256};
use sp_core::ed25519::{Public, Signature};

/// Represents a signature with its associated public key
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Sign {
    pub signatgure: Signature,
    pub key: Public,
}

// Define a transaction in the Centichain network
// The hash of the transaction is derived from the hashes of its inputs and outputs
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Transaction {
    pub hash: String,
    pub data: TrxData,
    pub sign: Sign,
    pub date: String,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct TrxData {
    pub from: String,
    pub to: Public,
    #[serde_as(as = "DisplayFromStr")]
    pub value: Decimal,
    #[serde_as(as = "DisplayFromStr")]
    pub fee: Decimal,
    pub salt: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TxRes {
    pub hash: String,
    pub status: String,
    pub description: String,
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

impl Transaction {
    /// Sends a new transaction to the network
    pub async fn make_and_send(
        wallet: String,
        private: String,
        to: String,
        value: String,
    ) -> Result<String, String> {
        let wallet = wallet.trim();
        let to = to.trim();
        let to: Public = to.parse().unwrap();
        let salt = rand::thread_rng().gen_range(0..10_000_000);
        let decimal_value = Decimal::from_str(&value).unwrap();

        let trx_data = TrxData {
            from: wallet.to_string(),
            to,
            value: decimal_value,
            fee: decimal_value * Decimal::from_str("0.01").unwrap(),
            salt,
        };

        let str_data = serde_json::to_string(&trx_data).unwrap();
        let hash = HashMaker::generate(&str_data);
        let sign = Sign {
            signatgure: centichain_keypair::CentichainKey::signing(&private, &hash).unwrap(),
            key: wallet.parse().unwrap(),
        };

        let transaction = Self {
            hash,
            data: trx_data,
            sign,
            date: "".to_string(),
        };

        let client = Client::new();
        let url = format!("https://centichain.org/jrpc/trx");

        match client.post(url).json(&transaction).send().await {
            Ok(res) => {
                let response: TxRes = res.json().await.unwrap();

                if response.status == "success".to_string() {
                    return Ok(response.status);
                } else {
                    return Err(response.description);
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}
