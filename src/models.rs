#[derive(Serialize, Deserialize, Debug)]
pub struct Status {
    pub code: bool,
}

#[derive(Serialize, Deserialize)]
pub struct IccSignRequest {
    pub pub_key: String,
    pub from_account: String,
    pub to_account: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize)]
pub struct IccKeyGenRequest {
    pub key_gen: String
}
#[derive(Serialize, Deserialize)]
pub struct IccKeyGenResponse {
    pub pk: String,
    pub sk: String
}

#[derive(Serialize, Deserialize)]
pub struct IccWalletSignRequest {
    pub message: String,
    pub sk: String,
}