use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IccError{
    PubkeyError,
    SecretError,
    KeypairError,
    ToPubkeyError,
    FromPubkeyError,
    FromSecretError,
    IpfsHashError,
    VerifyError,
    TransactionError,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorJson{
    pub error: String,
}

pub static UNKNOWN_ERROR: &str = "UNKNOWN_ERROR";
pub static PUBKEY_ERROR: &str = "PUBKEY_ERROR";
pub static SECRET_ERROR: &str = "SECRET_ERROR";
pub static TO_PUBKEY_ERROR: &str = "TO_PUBKEY_ERROR";
pub static FROM_PUBKEY_ERROR: &str = "FROM_PUBKEY_ERROR";
pub static IPFS_HASH_ERROR: &str = "IPFS_HASH_ERROR";
pub static VERIFY_ERROR: &str = "VERIFY_ERROR";
pub static TRANSACTION_ERROR: &str = "TRANSACTION_ERROR";

impl ErrorJson{
    pub fn new(error: &str) -> Self{
        Self{
            error: error.to_string(),
        }
    }
    pub fn from(err: IccError) -> Self{
        Self{
            error: match err {
                IccError::FromPubkeyError => FROM_PUBKEY_ERROR,
                IccError::ToPubkeyError => TO_PUBKEY_ERROR,
                IccError::SecretError => SECRET_ERROR,
                IccError::IpfsHashError => IPFS_HASH_ERROR,
                IccError::VerifyError => VERIFY_ERROR,
                IccError::TransactionError => TRANSACTION_ERROR,
                _ => UNKNOWN_ERROR,
            }.to_string(),
        }
    }
}

impl IccError{
    pub fn toJson(self) -> ErrorJson{
        ErrorJson::from(self)
    }
}