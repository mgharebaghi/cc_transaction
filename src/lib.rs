//! A library for handling cryptocurrency transactions on the Centichain network.
//!
//! This module provides functionality for creating, signing and sending transactions,
//! managing UTXOs (Unspent Transaction Outputs), and handling wallet operations.

use rand::Rng;
use reqwest::Client;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr}; 
use sha2::{Digest, Sha256};
use sp_core::ed25519::{Public, Signature};
use std::str::FromStr;

/// Represents a digital signature along with the signer's public key
/// Used to verify the authenticity of transactions
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Sign {
    /// The cryptographic signature
    pub signatgure: Signature,
    /// The public key of the signer
    pub key: Public,
}

/// Represents a transaction in the Centichain network
/// The transaction hash is derived from its data fields
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Transaction {
    /// SHA256 hash of the transaction data
    pub hash: String,
    /// Core transaction information
    pub data: TrxData,
    /// Digital signature of the transaction
    pub sign: Sign,
    /// Timestamp of the transaction
    pub date: String,
}

/// Contains the core data fields of a transaction
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct TrxData {
    /// Sender's wallet address
    pub from: String,
    /// Recipient's public key
    pub to: Public,
    /// Amount to transfer
    #[serde_as(as = "DisplayFromStr")]
    pub value: Decimal,
    /// Transaction fee
    #[serde_as(as = "DisplayFromStr")]
    pub fee: Decimal,
    /// Random value to prevent transaction replay attacks
    pub salt: i32,
}

/// Response structure for transaction submission
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TxRes {
    /// Transaction hash
    pub hash: String,
    /// Status of the transaction ("success" or error)
    pub status: String,
    /// Detailed description or error message
    pub description: String,
}

/// Utility struct for generating SHA256 hashes
pub struct HashMaker;

impl HashMaker {
    /// Generates a SHA256 hash of the input data
    /// 
    /// # Arguments
    /// * `data` - The string data to hash
    /// 
    /// # Returns
    /// A hexadecimal string representation of the hash
    pub fn generate(data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

impl Transaction {
    /// Creates and sends a new transaction to the Centichain network
    /// 
    /// # Arguments
    /// * `wallet` - The sender's wallet address
    /// * `private` - The sender's private key
    /// * `to` - The recipient's address
    /// * `value` - The amount to send
    /// 
    /// # Returns
    /// * `Ok(String)` - Success status
    /// * `Err(String)` - Error message if the transaction fails
    pub async fn make_and_send(
        wallet: String,
        private: String,
        to: String,
        value: String,
    ) -> Result<String, String> {
        let wallet = wallet.trim();
        
        let to = to.trim();
        match to.parse::<Public>() {
            Ok(recipent) => {
                // Generate random salt and calculate transaction values
                let salt = rand::thread_rng().gen_range(0..10_000_000);
                let decimal_value = Decimal::from_str(&value).unwrap().trunc_with_scale(12);
                let fee = decimal_value * Decimal::from_str("0.01").unwrap().trunc_with_scale(12);

                // Create transaction data structure
                let trx_data = TrxData {
                    from: wallet.to_string(),
                    to: recipent,
                    value: decimal_value,
                    fee: fee.trunc_with_scale(12),
                    salt,
                };

                // Generate transaction hash and sign it
                let str_data = serde_json::to_string(&trx_data).unwrap();
                let hash = HashMaker::generate(&str_data);
                let sign = Sign {
                    signatgure: centichain_keypair::CentichainKey::signing(&private, &hash)
                        .unwrap(),
                    key: wallet.parse().unwrap(),
                };

                // Create final transaction object
                let transaction = Self {
                    hash,
                    data: trx_data,
                    sign,
                    date: "".to_string(),
                };

                // Send transaction to the network
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
            Err(_) => return Err("Invalid recipient address format".to_string()),
        }
    }
}
