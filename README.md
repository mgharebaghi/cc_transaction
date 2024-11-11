# Centichain Transaction Library

A Rust library for handling cryptocurrency transactions on the Centichain network. This library provides comprehensive functionality for creating, signing, and sending transactions, managing UTXOs (Unspent Transaction Outputs), and handling wallet operations.

## Features

- Transaction creation and management
- UTXO (Unspent Transaction Output) handling
- Transaction signing with ED25519 keys
- Merkle tree operations for transaction hashing
- Support for both single and multi-signature transactions
- Automatic fee calculation
- Secure hash generation using SHA256

## Usage

### Creating and Sending a Transaction

```rust
use centichain_transactions::Transaction;

async fn send_money() -> Result<String, String> {
    let wallet = "your_wallet_public_key";
    let private_key = "your_private_key";
    let recipient = "recipient_wallet_address";
    let amount = "100.50"; // Amount in decimal format
    let result = Transaction::make_and_send(
        wallet.to_string(),
        private_key.to_string(),
        recipient.to_string(),
        amount.to_string()
    ).await?;

    Ok(result)
}
```

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
centichain-transactions = "0.9.0"
