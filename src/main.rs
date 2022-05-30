extern crate iron;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

mod models;

use iron::{Iron, Request, Response, IronResult};
use iron::status;

use self::models::Status;

fn hello_world(_: &mut Request) -> IronResult<Response> {
    let status = Status {
        code: "ok".to_string(),
    };
    let serialized = serde_json::to_string(&status).unwrap();
    Ok(Response::with((status::Ok, serialized)))
}

fn main() {
    println!("Running on http://localhost:8080");
    Iron::new(hello_world).http("localhost:8080").unwrap();
}