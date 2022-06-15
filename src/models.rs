
#[derive(Serialize, Deserialize)]
pub struct IccSignRequest {
    pub sender_hash: String,
    pub to_account: String,
    pub signature: String,
    pub validator_signature: String,
}

#[derive(Serialize, Deserialize)]
pub struct IccKeyGenRequest {
    pub key_gen: String
}
#[derive(Serialize, Deserialize)]
pub struct IccKeyGenResponse {
    pub sender_hash: String,
    pub sk: String,
    pub pk: String
}

#[derive(Serialize, Deserialize)]
pub struct IccWalletSignRequest {
    pub message: String,
    pub sk: String,
}