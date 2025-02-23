use base58::{ToBase58, FromBase58};
use serde::{Deserialize, Serialize};
use borsh::{BorshDeserialize, BorshSerialize};
use std::error::Error;

use crate::errors::IccError;


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
    pub fn decode(data: String) -> Result<[u8;32], IccError>{
        let data = data.from_base58();
        if data.is_err() {
            return Err(IccError::IpfsHashError);
        }
        let data = data.unwrap();

        let hash = IpfsHash::try_from_slice(data.as_slice());
        if hash.is_err() {
            return Err(IccError::IpfsHashError);
        }
        let hash = hash.unwrap().hash;

        Ok(hash)
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
    pub fn decode(data: String) ->  Result<QntPublicKey, IccError>{
        let arr = base64::decode(data);
        if arr.is_err() {
            return Err(IccError::PubkeyError);
        }
        let key = QntPublicKey::try_from_slice(arr.unwrap().as_slice());
        if key.is_err() {
            return Err(IccError::PubkeyError);
        }
        Ok(key.unwrap())
    }
    pub fn encode(self) -> String{
        base64::encode(self.try_to_vec().unwrap())
    }
}

impl QntSecretKey{
    pub fn decode(data: String) -> Result<QntSecretKey, IccError>{
        let arr = base64::decode(data);
        if arr.is_err() {
            return Err(IccError::SecretError);
        }
        let key = QntSecretKey::try_from_slice(arr.unwrap().as_slice());
        if key.is_err() {
            return Err(IccError::SecretError);
        }
        Ok(key.unwrap())
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
            public_key: QntPublicKey::decode(self.public_key).ok().unwrap(),
            secret_key: QntSecretKey::decode(self.secret_key).ok().unwrap(),
        }
    }
}

impl QntKeyJson{
    pub fn decodePublicKey(self) -> Result<EccKeyJson, IccError>{
        let key = QntPublicKey::decode(self.key);
        if key.is_err() {
            return Err(IccError::PubkeyError);
        }
        Ok(EccKeyJson{
            key: key.unwrap().ecc_key.to_base58(),
        })
    }
}