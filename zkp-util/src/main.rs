use std::env;

use next_gen_signatures::{crypto::zkp, Engine, BASE64_URL_SAFE_NO_PAD};

fn main() {
    let args = env::args();

    let encoded = args.skip(1).next().expect("No credential to decode");

    let credential = zkp::Credential::deserialize_encoded(&encoded);

    let json = credential.as_json();

    println!("{json:#}");
}
