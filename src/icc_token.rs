use serde::{Deserialize, Serialize};
use borsh::{BorshDeserialize, BorshSerialize};
use crate::errors::IccError;

use crate::icc_types::{
    QntPublicKey,
};

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub enum TokenInstruction{
    SaveHash {
        hash: [u8;32]
    },
    Transfer {
        r_number: u64,
        amount: u64
    },
    Airdrop{
        r_number: u64,
        amount: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstructionSaveHash{
    hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstructionTransfer{
    r_number: u64,
    amount: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstructionAirdrop{
    r_number: u64,
    amount: u64,
}



#[derive(Debug, Serialize, Deserialize)]
pub struct EncodeData{
    pub data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecodeData{
    pub data: Vec<u8>,
}


#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct QntTransaction{
    pub from_qnt_pubkey: QntPublicKey,
    pub to_qnt_pubkey: QntPublicKey,
    amount: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QntTransactionJson{
    from_qnt_pubkey: String,
    to_qnt_pubkey: String,
    amount: u64,
}



impl TokenInstruction{
    pub fn encode(&self) -> DecodeData{
        DecodeData{
            data: self.try_to_vec().unwrap(),
        }
    }
}

impl InstructionSaveHash{
    pub fn encode(self) -> DecodeData{
        TokenInstruction::SaveHash{
            hash: base64::decode(self.hash).unwrap().try_into().unwrap(),
        }.encode()
    }
}

impl InstructionTransfer{
    pub fn encode(self) -> DecodeData{
        TokenInstruction::Transfer{
            r_number: self.r_number,
            amount: self.amount,
        }.encode()
    }
}

impl InstructionAirdrop{
    pub fn encode(self) -> DecodeData{
        TokenInstruction::Airdrop{
            r_number: self.r_number,
            amount: self.amount,
        }.encode()
    }
}



impl QntTransactionJson{
    pub fn parse(self) -> Result<QntTransaction, IccError>{
        let from_pubkey = QntPublicKey::decode(self.from_qnt_pubkey);
        if from_pubkey.is_err() {
            return Err(IccError::FromPubkeyError);
        }
        let from_pubkey = from_pubkey.unwrap();

        let to_pubkey = QntPublicKey::decode(self.to_qnt_pubkey);
        if to_pubkey.is_err() {
            return Err(IccError::ToPubkeyError);
        }
        let to_pubkey = to_pubkey.unwrap();
        
        Ok(QntTransaction{
            from_qnt_pubkey: from_pubkey,
            to_qnt_pubkey: to_pubkey,
            amount: self.amount,
        })
    }
    pub fn decode(data: EncodeData) -> QntTransactionJson{
        QntTransaction::try_from_slice(base64::decode(data.data).unwrap().as_slice()).unwrap().decode()
    }
}

impl QntTransaction{
    pub fn decode(self) -> QntTransactionJson{
        QntTransactionJson{
            from_qnt_pubkey: self.from_qnt_pubkey.encode(),
            to_qnt_pubkey: self.to_qnt_pubkey.encode(),
            amount: self.amount,
        }
    }
    pub fn encode(self) -> EncodeData{
        EncodeData {
            data: base64::encode(self.try_to_vec().unwrap()),
        }
    }
}