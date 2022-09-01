use base58::{FromBase58, ToBase58};
use serde::{Deserialize, Serialize};
use borsh::{BorshDeserialize, BorshSerialize};
use crate::icc_types::IpfsHash;

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct QntTransactionInfo{
    pub from_pubkey: [u8;64],
    pub to_pubkey: [u8;64],
    pub transaction_signature: [u8;64],
    pub sender_signature_hash: [u8;32],
    pub validator_signature_hash: [u8;32],
    pub amount: u64,
    pub previous_block_hash: [u8;32],
}

#[derive(Serialize, Deserialize, Debug)]
pub struct QntTransactionInfoJson{
    from_pubkey: String,
    to_pubkey: String,
    transaction_signature: String,
    sender_signature_hash: String,
    validator_signature_hash: String,
    amount: u64,
    pub block_hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct InfoJson {
    pub public_key: String,
    pub block_hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct InfoListJson {
    pub list: Vec<QntTransactionInfoJson>,
}

impl QntTransactionInfoJson{
    pub fn encode(self) -> Vec<u8>{
        let block_hash = if self.block_hash == "" {
            [0u8;32]
        }else{
            IpfsHash::decode(self.block_hash).unwrap()
        };
        let tx = QntTransactionInfo{
            from_pubkey: base64::decode(self.from_pubkey).unwrap().try_into().unwrap(),
            to_pubkey: base64::decode(self.to_pubkey).unwrap().try_into().unwrap(),
            transaction_signature: self.transaction_signature.from_base58().unwrap().try_into().unwrap(),
            sender_signature_hash: base64::decode(self.sender_signature_hash).unwrap().try_into().unwrap(),
            validator_signature_hash: base64::decode(self.validator_signature_hash).unwrap().try_into().unwrap(),
            amount: self.amount,
            previous_block_hash: block_hash,
        };
        tx.try_to_vec().unwrap()
    }
    pub fn decode(data: Vec<u8>) -> QntTransactionInfoJson{
        let tx = QntTransactionInfo::try_from_slice(data.as_slice()).unwrap();
        QntTransactionInfoJson{
            from_pubkey: base64::encode(tx.from_pubkey),
            to_pubkey: base64::encode(tx.to_pubkey),
            transaction_signature: tx.transaction_signature.to_base58(),
            sender_signature_hash: base64::encode(tx.sender_signature_hash),
            validator_signature_hash: base64::encode(tx.validator_signature_hash),
            amount: tx.amount,
            block_hash: IpfsHash::encode(tx.previous_block_hash),
        }
    }
    pub fn from(tx: &QntTransactionInfo) -> QntTransactionInfoJson{
        QntTransactionInfoJson{
            from_pubkey: base64::encode(tx.from_pubkey),
            to_pubkey: base64::encode(tx.to_pubkey),
            transaction_signature: tx.transaction_signature.to_base58(),
            sender_signature_hash: base64::encode(tx.sender_signature_hash),
            validator_signature_hash: base64::encode(tx.validator_signature_hash),
            amount: tx.amount,
            block_hash: IpfsHash::encode(tx.previous_block_hash),
        }
    }
}