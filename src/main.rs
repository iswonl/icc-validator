use actix_cors::Cors;
use actix_web;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder, http::uri::Scheme};
use base58::{FromBase58, ToBase58};
use borsh::BorshDeserialize;
use futures::TryStreamExt;
use ipfs_api::{IpfsApi, IpfsClient, TryFromUri, Form};
use std::io::Cursor;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use pqcrypto_traits::sign::*;
use pqcrypto_dilithium::dilithium2::*;
use sha2::{Sha256, Digest};
use std::{env};

pub mod icc_types;
pub mod icc_token;
pub mod save_data;
pub mod hasher;

use icc_types::*;
use icc_token::*;
use save_data::*;
use hasher::*;


#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref VALIDATOR_KEYPAIR: Mutex<IccKeypair> = {
        let (pk, sk) = keypair();
        let sk_str = base64::encode(sk.as_bytes());
        let pk_str = base64::encode(pk.as_bytes());
        let keys = IccKeypair{
            public_key: pk_str,
            secret_key: sk_str,
        };
        Mutex::new(keys)
    };    
}

lazy_static! {
    pub static ref BACKEND_HOST: String = env::var("BACKEND_HOST").expect("Missing BACKEND_HOST env variable");
    pub static ref BACKEND_PORT: u16 = env::var("BACKEND_PORT").expect("Missing BACKEND_PORT env variable").parse().unwrap();
    pub static ref IPFS_HOST: String = env::var("IPFS_HOST").expect("Missing IPFS_HOST env variable");
    pub static ref IPFS_PORT: u16 = env::var("IPFS_PORT").expect("Missing IPFS_PORT env variable").parse().unwrap();
}

pub async fn ipfsSave(client: &web::Data<Mutex<IpfsClient>>, data: Vec<u8>) -> Result<[u8;32], String>{
    match client.lock().unwrap().add(Cursor::new(data)).await{
        Ok(res) => Ok(IpfsHash::decode(res.hash)),
        Err(e) => Err(e.to_string()),
    }
}

pub async fn ipfsGet(client: &web::Data<Mutex<IpfsClient>>, hash: [u8;32]) -> Vec<u8>{
    let data = client.lock().unwrap()
    .cat(IpfsHash::encode(hash).as_str())
    .map_ok(|ok| ok.to_vec())
    .try_concat()
    .await.unwrap();
    data
}

#[derive(Serialize, Deserialize)]
pub struct StoreData {
    name: String,
    data: String,
}

#[get("/")]
async fn hello() -> impl Responder {
    println!("hello world!");
    HttpResponse::Ok().body("Hello world!")
}

#[post("/get_transaction_info_list")]
async fn get_transaction_info_list(client: web::Data<Mutex<IpfsClient>>, data: web::Json<InfoJson>) -> Result<HttpResponse, actix_web::Error> {
    println!("-----get transaction info list-----");
    let pubkey: [u8;64] = base64::decode(data.0.public_key).unwrap().try_into().unwrap();

    let mut hash = IpfsHash::decode(data.0.block_hash);
    
    let mut list: Vec<QntTransactionInfoJson> = vec![];

    let mut do_scan = true;

    while(do_scan){
        let data = ipfsGet(&client, hash).await;
        let info = &QntTransactionInfo::try_from_slice(data.as_slice()).unwrap();
        
        if(info.from_pubkey == pubkey || info.to_pubkey == pubkey){
            let info = QntTransactionInfoJson::from(&info);
            list.push(info);
        }

        do_scan = info.from_pubkey != info.to_pubkey;
        hash = info.previous_block_hash;
    }
    
    let data = InfoListJson{
        list: list,
    };
    Ok(HttpResponse::Ok().json(data))
}

#[post("/save_transaction_info")]
async fn save_transaction_info(client: web::Data<Mutex<IpfsClient>>, data: web::Json<DecodeData>) -> Result<HttpResponse, actix_web::Error> {
    println!("-----save transaction info-----");

    let data = data.0.data;
    let hash = ipfsSave(&client, data).await.unwrap();
    let hash = IpfsHash::encode(hash);
    println!("save hash: {}", hash);

    let data = EncodeData{
        data: hash,
    };

    Ok(HttpResponse::Ok().json(data))
}

#[post("/get_transaction_info")]
async fn get_transaction_info(client: web::Data<Mutex<IpfsClient>>, data: web::Json<EncodeData>) -> Result<HttpResponse, actix_web::Error> {
    println!("-----get transaction info-----");
    println!("get data from hash: {}", data.0.data);

    let hash = IpfsHash::decode(data.0.data);
    let data = ipfsGet(&client, hash).await;
    let data = DecodeData{
        data: data,
    };

    Ok(HttpResponse::Ok().json(data))
}

#[post("/encode_transaction_info")]
async fn encode_transaction_info(data: web::Json<QntTransactionInfoJson>) -> Result<HttpResponse, actix_web::Error> {
    println!("-----encode transaction info-----");
    let data = DecodeData{data: data.0.encode()};
    Ok(HttpResponse::Ok().json(data))
}

#[post("/decode_transaction_info")]
async fn decode_transaction_info(data: web::Json<DecodeData>) -> Result<HttpResponse, actix_web::Error> {
    println!("-----decode transaction info-----");
    let data = QntTransactionInfoJson::decode(data.0.data);
    Ok(HttpResponse::Ok().json(data))
}

#[post("/encode_transaction")]
async fn encode_transaction(data: web::Json<QntTransactionJson>) -> Result<HttpResponse, actix_web::Error> {
    println!("-----encode transaction-----");
    let data = data.0.parse().encode();
    Ok(HttpResponse::Ok().json(data))
}

#[post("/decode_transaction")]
async fn decode_transaction(data: web::Json<EncodeData>) -> Result<HttpResponse, actix_web::Error> {
    println!("-----decode transaction-----");
    let data = QntTransactionJson::decode(data.0);
    Ok(HttpResponse::Ok().json(data))
}

#[post("/transfer_hash")]
async fn transfer_hash(data: web::Json<HashDataTransfer>) -> Result<HttpResponse, actix_web::Error> {
    println!("-----create transfer hash-----");
    let hash = EncodeData{data: data.0.sha2()};
    println!("tx data hash: {}", hash.data);
    Ok(HttpResponse::Ok().json(hash))
}

#[post("/airdrop_hash")]
async fn airdrop_hash(data: web::Json<HashDataAirdrop>) -> Result<HttpResponse, actix_web::Error> {
    println!("-----create airdrop hash-----");
    let hash = EncodeData{data: data.0.sha2()};
    println!("tx data hash: {}", hash.data);
    Ok(HttpResponse::Ok().json(hash))
}

#[post("/tx_save_hash")]
async fn tx_save_hash(data: web::Json<InstructionSaveHash>) -> Result<HttpResponse, actix_web::Error> {
    println!("-----create save hash-----");
    let tx = data.0.encode();
    Ok(HttpResponse::Ok().json(tx))
}

#[post("/tx_transfer")]
async fn tx_transfer(data: web::Json<InstructionTransfer>) -> Result<HttpResponse, actix_web::Error> {
    println!("-----create tx transfer-----");
    let tx = data.0.encode();
    Ok(HttpResponse::Ok().json(tx))
}

#[post("/tx_airdrop")]
async fn tx_airdrop(data: web::Json<InstructionAirdrop>) -> Result<HttpResponse, actix_web::Error> {
    println!("-----create tx airdrop-----");
    let tx = data.0.encode();
    Ok(HttpResponse::Ok().json(tx))
}

#[post("/get_ecc_pubkey")]
async fn get_ecc_pubkey(client: web::Data<Mutex<IpfsClient>>, data: web::Json<QntKeyJson>) -> Result<HttpResponse, actix_web::Error> {
    println!("-----get ecc pubkey-----");
    let ecc_key = data.0.decodePublicKey();
    println!("ecc_pubkey: {}", ecc_key.key);
    Ok(HttpResponse::Ok().json(ecc_key))
}

#[post("/qnt_keypair")]
async fn qnt_keypair(client: web::Data<Mutex<IpfsClient>>, data: web::Json<EccKeyJson>) -> Result<HttpResponse, actix_web::Error> {
    println!("-----create qnt keypair-----");
    let ecc_pubkey = data.0.key;
    println!("ecc_pubkey: {}", ecc_pubkey);

    let (pk, sk) = keypair();
    let icc_pubkey = pk.as_bytes().to_vec();
    let icc_secret = sk.as_bytes().to_vec();
    println!("icc_pubkey: {}", base64::encode(&icc_pubkey));

    let icc_pk_hash = ipfsSave(&client, icc_pubkey).await.unwrap();

    println!("icc_pubkey_ipfs_hash: {}", base64::encode(icc_pk_hash));

    let qnt_pubkey = QntPublicKey{
        ecc_key: ecc_pubkey.from_base58().unwrap().try_into().unwrap(),
        icc_key_hash: icc_pk_hash,
    };

    let qnt_secret = QntSecretKey{
        icc_key: icc_secret,
    };

    let qnt_keypair = QntKeypair{
        public_key: qnt_pubkey,
        secret_key: qnt_secret,
    };

    let qnt_keypair = qnt_keypair.encode();

    println!("qnt_pubkey: {}", qnt_keypair.public_key);
    Ok(HttpResponse::Ok().json(qnt_keypair))
}

#[post("/icc_sign")]
async fn icc_sign(client: web::Data<Mutex<IpfsClient>>, data: web::Json<IccSign>) -> Result<HttpResponse, actix_web::Error> {
    println!("-----sign message-----");
    let data = data.0;
    let message = base64::decode(data.message).unwrap();
    let qnt_secret = QntSecretKey::decode(data.secret_key).icc_key;

    let sk  =  pqcrypto_dilithium::dilithium2::SecretKey::from_bytes(qnt_secret.as_slice()).unwrap();
    let det_sig = detached_sign(&message, &sk);
    let sign_msg = ipfsSave(&client, det_sig.as_bytes().to_vec()).await.unwrap();

    let data = Signature{
        signature: base64::encode(sign_msg),
    };

    println!("ipfs_signature_hash: {}", data.signature);
    Ok(HttpResponse::Ok().json(data))
}

#[post("/icc_verify")]
async fn icc_verify(client: web::Data<Mutex<IpfsClient>>, data: web::Json<VerifyMessage>) -> Result<HttpResponse, actix_web::Error> {
    println!("-----verify message-----");
    let data = data.0;
    let qnt_key = QntPublicKey::decode(data.public_key);

    let pk = ipfsGet(&client, qnt_key.icc_key_hash).await;
    let sig = ipfsGet(&client, base64::decode(data.signature).unwrap().try_into().unwrap()).await;
    let msg = base64::decode(data.message).unwrap();
    
    let pk = pqcrypto_dilithium::dilithium2::PublicKey::from_bytes(pk.as_slice()).unwrap();
    let sig = pqcrypto_dilithium::dilithium2::DetachedSignature::from_bytes(sig.as_slice()).unwrap();
    let isok = !verify_detached_signature(&sig, &msg, &pk).ok().is_none();

    let mut data: Signature = Signature{
        signature: "".to_string(),
    };

    if isok {
        let keys = VALIDATOR_KEYPAIR.lock().unwrap();
        let sk_bytes = base64::decode(&keys.secret_key).unwrap();
        let sk =  pqcrypto_dilithium::dilithium2::SecretKey::from_bytes(&sk_bytes).unwrap();
        let sig = ipfsSave(&client, sign(&msg, &sk).as_bytes().to_vec()).await.unwrap();
        data.signature = base64::encode(sig);
        println!("ipfs_validator_signature_hash: {}", data.signature);
    }
    
    Ok(HttpResponse::Ok().json(data))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let cors = Cors::permissive();
        let client: Mutex<IpfsClient> = Mutex::new(IpfsClient::from_host_and_port(Scheme::HTTP, IPFS_HOST.as_str(), *IPFS_PORT).unwrap());
        App::new()
            .wrap(cors)
            .data(client)
            .service(hello)

            .service(get_ecc_pubkey)
            .service(qnt_keypair)
            .service(icc_sign)
            .service(icc_verify)

            .service(encode_transaction_info)
            .service(decode_transaction_info)
            .service(encode_transaction)
            .service(decode_transaction)
            .service(transfer_hash)
            .service(airdrop_hash)
            .service(tx_save_hash)
            .service(tx_transfer)
            .service(tx_airdrop)

            .service(save_transaction_info)
            .service(get_transaction_info)
            .service(get_transaction_info_list)
    })
    .bind((BACKEND_HOST.as_str(), *BACKEND_PORT))?
    // .bind(("127.0.0.1", 8000))?
    .run()
    .await
}