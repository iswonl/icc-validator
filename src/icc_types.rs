use base58::{ToBase58, FromBase58};
use serde::{Deserialize, Serialize};
use borsh::{BorshDeserialize, BorshSerialize};


#[derive(BorshDeserialize, BorshSerialize)]
pub struct IpfsHash {
    pub hash_function: u8,
    pub size: u8,
    pub hash: [u8;32],
}

#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct QntPublicKey {
    pub ecc_key: [u8;32],
    pub icc_key_hash: [u8;32],
}

#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct QntSecretKey {
    pub icc_key: Vec<u8>,
}

pub struct QntKeypair {
    pub public_key: QntPublicKey,
    pub secret_key: QntSecretKey,
}


#[derive(Serialize, Deserialize)]
pub struct QntKeyJson {
    pub key: String,
}

#[derive(Serialize, Deserialize)]
pub struct EccKeyJson {
    pub key: String,
}

#[derive(Serialize, Deserialize)]
pub struct QntKeypairJson {
    pub public_key: String,
    pub secret_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct EccKeypair {
    pub public_key: String,
    pub secret_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct IccKeypair {
    pub public_key: String,
    pub secret_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct IccSign {
    pub message: String,
    pub secret_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct Signature {
    pub signature: String,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyMessage {
    pub message: String,
    pub signature: String,
    pub public_key: String,
}

impl IpfsHash{
    pub fn decode(data: String) -> [u8;32]{
        IpfsHash::try_from_slice(data.from_base58().unwrap().as_slice()).unwrap().hash
    }
    pub fn encode(hash: [u8;32]) -> String{
        IpfsHash{
            hash_function: 18,
            size: 32,
            hash: hash,
        }.try_to_vec().unwrap().to_base58()
    }
}

impl QntPublicKey{
    pub fn decode(data: String) -> QntPublicKey{
        QntPublicKey::try_from_slice(base64::decode(data).unwrap().as_slice()).unwrap()
    }
    pub fn encode(self) -> String{
        base64::encode(self.try_to_vec().unwrap())
    }
}

impl QntSecretKey{
    pub fn decode(data: String) -> QntSecretKey{
        QntSecretKey::try_from_slice(base64::decode(data).unwrap().as_slice()).unwrap()
    }
    pub fn encode(self) -> String{
        base64::encode(self.try_to_vec().unwrap())
    }
}

impl QntKeypair{
    pub fn encode(self) -> QntKeypairJson{
        QntKeypairJson{
            public_key: self.public_key.encode(),
            secret_key: self.secret_key.encode(),
        }
    }
}

impl QntKeypairJson{
    pub fn parse(self) -> QntKeypair{
        QntKeypair{
            public_key: QntPublicKey::decode(self.public_key),
            secret_key: QntSecretKey::decode(self.secret_key),
        }
    }
}

impl QntKeyJson{
    pub fn decodePublicKey(self) -> EccKeyJson{
        EccKeyJson{
            key: QntPublicKey::decode(self.key).ecc_key.to_base58(),
        }
    }
}