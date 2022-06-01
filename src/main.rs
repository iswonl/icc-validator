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
use self::models::Status;
use pqcrypto_traits::sign::*;
use pqcrypto_dilithium::dilithium2::*;
use iron::headers;

fn verify(s: &str) -> String {
    let icc: IccSignRequest = serde_json::from_str(s).unwrap();

    let pubkey = base64::decode(icc.pub_key).unwrap();
    let msg = base64::decode(icc.from_account).unwrap();
    let signature = base64::decode(icc.signature).unwrap();
    
    let pk = pqcrypto_dilithium::dilithium2::PublicKey::from_bytes(pubkey.as_slice()).unwrap();
    let sig = pqcrypto_dilithium::dilithium2::DetachedSignature::from_bytes(signature.as_slice()).unwrap();
    let  code =  !verify_detached_signature(&sig, &msg, &pk).ok().is_none();
    
    let status = Status {
        code: code,
    };
    let serialized = serde_json::to_string(&status).unwrap();
    println!("Verification code: {0}", status.code);

    return serialized;
}

// fn generate(s: &str) -> bool {
// }

fn icc_verify(request: &mut Request) -> IronResult<Response> {
    println!( "new request {0}", request.method);
    let mut serialized = "".to_string();

    if  request.method == Method::POST {
        let cnt = request.get_body_contents().unwrap();
        let s = std::str::from_utf8(cnt).unwrap();
        println!( "{0}", s);
        if s.to_string().contains("pub_key") {
            serialized =  verify(s);
        } else if s.to_string().contains("key_gen") {
            let (pk, sk) = keypair();
            let pk = base64::encode(pk.as_bytes());
            let sk = base64::encode(sk.as_bytes());
            let r = IccKeyGenResponse {pk: pk,sk: sk};
            serialized = serde_json::to_string(&r).unwrap();
        }  else if s.to_string().contains("message") {
            let icc: IccWalletSignRequest = serde_json::from_str(s).unwrap();
            let message =base64::decode(icc.message).unwrap();
            let sk_bytes =base64::decode(icc.sk).unwrap();
            let sk  = pqcrypto_dilithium::dilithium2::SecretKey::from_bytes(sk_bytes.as_slice()).unwrap();
            let det_sig = detached_sign(&message, &sk);
            let sm = base64::encode(det_sig.as_bytes());
            let r = IccWalletSignRequest {message: sm,sk: "".to_string()};
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

    println!("Running on http://localhost:8080");
    Iron::new(icc_verify).http("0.0.0.0:8080");
}