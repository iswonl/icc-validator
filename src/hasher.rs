use base58::FromBase58;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

#[derive(Debug, Serialize, Deserialize)]
pub struct HashDataTransfer{
    from_pubkey: String,
    to_pubkey: String,
    data_pubkey: String,
    r_number: u64,
    from_balance: u64,
    to_balance: u64,
    amount: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HashDataAirdrop{
    to_pubkey: String,
    data_pubkey: String,
    r_number: u64,
    amount: u64,
}

impl HashDataTransfer{
    pub fn sha2(self) -> String{
        let mut hasher = Sha256::new();
        hasher.update(self.from_pubkey.from_base58().unwrap());
        hasher.update(self.to_pubkey.from_base58().unwrap());
        hasher.update(self.data_pubkey.from_base58().unwrap());
        hasher.update(self.r_number.to_be_bytes());
        hasher.update(self.from_balance.to_be_bytes());
        hasher.update(self.to_balance.to_be_bytes());
        hasher.update(self.amount.to_be_bytes());
        base64::encode(hasher.finalize())
    }
}

impl HashDataAirdrop{
    pub fn sha2(self) -> String{
        let mut hasher = Sha256::new();
        hasher.update(self.to_pubkey.from_base58().unwrap());
        hasher.update(self.data_pubkey.from_base58().unwrap());
        hasher.update(self.r_number.to_be_bytes());
        hasher.update(self.amount.to_be_bytes());
        base64::encode(hasher.finalize())
    }
}