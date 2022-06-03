extern crate iron;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
use iron::method::Method;
use iron::{StatusCode};
mod models;
use iron::{Iron, Request, Response, IronResult};
use crate::models::{IccSignRequest, IccKeyGenResponse, IccWalletSignRequest};
use pqcrypto_traits::sign::*;
use pqcrypto_dilithium::dilithium2::*;
use iron::headers;
use std::collections::HashMap;
use std::sync::Mutex;
use sha2::{Sha256, Digest};
#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref HASHMAP: Mutex<HashMap<String, String>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };    
}
lazy_static! {
    static ref VALIDATOR_SK: Mutex<String> = {
        let (_, sk) = keypair();
        let sk_str = base64::encode(sk.as_bytes());
        Mutex::new(sk_str)
    };    
}

fn val_sign(message: String) -> String {
    let s = VALIDATOR_SK.lock().unwrap();
    let b = base64::decode(s.as_str()).unwrap();
    let sk =  pqcrypto_dilithium::dilithium2::SecretKey::from_bytes(&b).unwrap();
    sha2(sign(message.as_bytes(), &sk).as_bytes())
}

fn verify(s: &str) -> String {
    let icc: IccSignRequest = serde_json::from_str(s).unwrap();
    let map = HASHMAP.lock().unwrap();
    let pub_key_str = map.get(&icc.pk_hash).unwrap();
    let pubkey = base64::decode(pub_key_str).unwrap();

    let msg = base64::decode(icc.from_account).unwrap();
    let sig_str = map.get(&icc.signature).unwrap();
    let signature = base64::decode(sig_str).unwrap();
    
    let pk = pqcrypto_dilithium::dilithium2::PublicKey::from_bytes(pubkey.as_slice()).unwrap();
    let sig = pqcrypto_dilithium::dilithium2::DetachedSignature::from_bytes(signature.as_slice()).unwrap();
    let  isok =  !verify_detached_signature(&sig, &msg, &pk).ok().is_none();


    let mut resp_icc: IccSignRequest = serde_json::from_str(s).unwrap();
    if isok {
        resp_icc.validator_signature = val_sign(s.to_string());
    }

    let serialized = serde_json::to_string(&resp_icc).unwrap();
    println!("Verification: {0}", serialized);

    return serialized;
}

// fn generate(s: &str) -> bool {
// }
fn sha2(slice:&[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(slice);
    let result = hasher.finalize();
    return base64::encode(result)
}
fn icc_verify(request: &mut Request) -> IronResult<Response> {
    println!( "new request {0}", request.method);
    let mut serialized = "".to_string();


    if  request.method == Method::POST {
        let cnt = request.get_body_contents().unwrap();
        let s = std::str::from_utf8(cnt).unwrap();
        println!( "{0}", s);
        if s.to_string().contains("pk_hash") {
            serialized =  verify(s);
        } else if s.to_string().contains("key_gen") {
            let (pk, sk) = keypair();
            let pk_str = base64::encode(pk.as_bytes());
            let pk_hash= sha2(pk.as_bytes());

            let mut map = HASHMAP.lock().unwrap();
            map.insert(pk_hash.clone(), pk_str);


            let sk = base64::encode(sk.as_bytes());
            let r = IccKeyGenResponse {pk_hash: pk_hash,sk: sk};
            serialized = serde_json::to_string(&r).unwrap();
        }  else if s.to_string().contains("message") {
            let icc: IccWalletSignRequest = serde_json::from_str(s).unwrap();
            let message =base64::decode(icc.message).unwrap();
            let sk_bytes =base64::decode(icc.sk).unwrap();
            let sk  = pqcrypto_dilithium::dilithium2::SecretKey::from_bytes(sk_bytes.as_slice()).unwrap();
            let det_sig = detached_sign(&message, &sk);
            let sm = base64::encode(det_sig.as_bytes());
            let sig_hash = sha2(det_sig.as_bytes());

            let mut map = HASHMAP.lock().unwrap();
            map.insert(sig_hash.clone(), sm);

            let r = IccWalletSignRequest {message: sig_hash,sk: "".to_string()};
            serialized = serde_json::to_string(&r).unwrap();
        }
      
    }

    
    Ok(Response::with((
        iron::modifiers::Header(
            headers::CONTENT_TYPE,
            iron::mime::APPLICATION_JSON.as_ref().parse().unwrap(),
        ),
        StatusCode::OK, 
        serialized)))
}


fn main() {
    println!( "Starting ICC validator");
    let message = vec![0, 1, 2, 3, 4, 5];
    let (pk, sk) = keypair();
    let sm = sign(&message, &sk);
    let verifiedmsg = open(&sm, &pk).unwrap();
    assert!(verifiedmsg == message);

    println!("Running on http://0.0.0.0:8080");
    Iron::new(icc_verify).http("0.0.0.0:8080");
}