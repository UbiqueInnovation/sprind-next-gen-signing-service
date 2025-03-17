use rocket::{get, launch, routes, serde::json::Json};

use next_gen_signatures::{Engine, BASE64_URL_SAFE_NO_PAD};
use rocket_errors::anyhow;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, rocket::serde::Serialize, rocket::serde::Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct KeyPair {
    pub public_key: String,
    pub secret_key: String,
}

mod fips204_routes {
    use super::*;
    use next_gen_signatures::generate_crypto_routes;

    generate_crypto_routes!(Fips204MlDsa44Provider);
    generate_crypto_routes!(Fips204MlDsa65Provider);
    generate_crypto_routes!(Fips204MlDsa87Provider);
}

mod bbs_plus_routes {
    use std::collections::BTreeMap;

    use super::*;
    use next_gen_signatures::{common::CryptoProvider, generate_crypto_routes};

    generate_crypto_routes!(BbsPlusG1Provider);
    generate_crypto_routes!(BbsPlusG2Provider);

    #[get("/pok/create?<signature>&<messages>&<nonce>&<revealed_indexes>")]
    #[allow(non_snake_case)]
    pub fn BbsPlusG1Provider_create_pok_of_sig(
        signature: String,
        messages: Vec<String>,
        nonce: String,
        revealed_indexes: Vec<usize>,
    ) -> Json<String> {
        use next_gen_signatures::{crypto::BbsPlusG1Provider as Provider, BASE64_URL_SAFE_NO_PAD};

        let signature = BASE64_URL_SAFE_NO_PAD.decode(signature).unwrap();
        let revealed_indexes = revealed_indexes.into_iter().collect();
        let proof =
            Provider::create_pok_of_sig(signature, messages, nonce, revealed_indexes).unwrap();

        Json(BASE64_URL_SAFE_NO_PAD.encode(proof))
    }

    #[get("/pok/verify?<proof>&<revealed_messages>&<public_key>&<nonce>&<message_count>")]
    #[allow(non_snake_case)]
    pub fn BbsPlusG1Provider_verify_pok_of_sig(
        proof: String,
        revealed_messages: BTreeMap<usize, String>,
        public_key: String,
        nonce: String,
        message_count: u32,
    ) -> Json<bool> {
        use next_gen_signatures::{crypto::BbsPlusG1Provider as Provider, BASE64_URL_SAFE_NO_PAD};

        let proof = BASE64_URL_SAFE_NO_PAD.decode(proof).unwrap();

        let public_key = BASE64_URL_SAFE_NO_PAD.decode(public_key).unwrap();
        let public_key = Provider::pk_from_bytes(public_key).unwrap();

        let revealed_messages = revealed_messages.into_iter().collect();

        let success =
            Provider::verify_pok_of_sig(proof, revealed_messages, public_key, nonce, message_count)
                .unwrap();

        Json(success)
    }
}

mod zkp_routes {
    use std::collections::HashMap;

    use next_gen_signatures::{
        crypto::zkp::{self, Circuits, ProofRequirement},
        Engine, BASE64_URL_SAFE_NO_PAD,
    };
    use rand::rngs::OsRng;
    use rocket::{get, post, serde::json::Json};
    use serde_json::{json, Value};

    use crate::KeyPair;

    #[get("/keypair")]
    pub fn gen_keypair() -> Json<KeyPair> {
        let mut rng = OsRng;

        let (pk, sk) = zkp::generate_keypair(&mut rng);
        let key_pair = KeyPair {
            public_key: pk,
            secret_key: sk,
        };

        Json(key_pair)
    }

    #[post(
        "/issue?<issuer_pk>&<issuer_sk>&<issuer_id>&<issuer_key_id>&<expiry_months>",
        data = "<data>"
    )]
    pub async fn issue(
        data: String,
        issuer_pk: String,
        issuer_sk: String,
        issuer_id: String,
        issuer_key_id: String,
        expiry_months: Option<u32>,
    ) -> Json<Value> {
        let mut rng = OsRng;

        let data = BASE64_URL_SAFE_NO_PAD.decode(&data).unwrap();
        let data = String::from_utf8(data).unwrap();
        let data = serde_json::from_str::<Value>(&data).unwrap();

        let expiry_months = expiry_months.unwrap_or(36);

        let credential = zkp::issue(
            &mut rng,
            data,
            issuer_pk,
            issuer_sk,
            &issuer_id,
            &issuer_key_id,
            expiry_months,
        )
        .await;

        Json(credential.serialize())
    }

    #[get("/proving-keys?<definition>")]
    pub fn gen_proving_keys(definition: String) -> Json<Circuits> {
        let mut rng = OsRng;

        let reqs = {
            let bytes = BASE64_URL_SAFE_NO_PAD.decode(definition).unwrap();
            let str = String::from_utf8(bytes).unwrap();
            serde_json::from_str::<Vec<ProofRequirement>>(&str).unwrap()
        };

        let circuits = zkp::circuits::generate_circuits(&mut rng, &reqs);

        Json(circuits)
    }

    #[post("/present?<issuer_pk>&<issuer_id>&<issuer_key_id>", data = "<data>")]
    pub async fn present(
        data: Json<Value>,
        issuer_pk: String,
        issuer_id: String,
        issuer_key_id: String,
    ) -> Json<Value> {
        let mut rng = OsRng;

        let credential = data["credential"].as_str().unwrap().to_string();
        let definition = data["definition"].as_str().unwrap().to_string();
        let proving_keys = data["proving_keys"].as_str().unwrap().to_string();

        let credential = zkp::Credential::deserialize_encoded(&credential);

        let reqs = {
            let bytes = BASE64_URL_SAFE_NO_PAD.decode(definition).unwrap();
            let str = String::from_utf8(bytes).unwrap();
            serde_json::from_str::<Vec<ProofRequirement>>(&str).unwrap()
        };

        let proving_keys = {
            let bytes = BASE64_URL_SAFE_NO_PAD.decode(proving_keys).unwrap();
            let str = String::from_utf8(bytes).unwrap();
            serde_json::from_str::<HashMap<String, String>>(&str).unwrap()
        };

        let (pres, _db) = zkp::present(
            &mut rng,
            credential,
            &reqs,
            &proving_keys,
            issuer_pk,
            &issuer_id,
            &issuer_key_id,
        )
        .await;

        // TODO: Do something with the device binding

        Json(json!({
            "proof": pres.serialize(),
        }))
    }

    #[post(
        "/verify?<issuer_pk>&<verifying_keys>&<definition>&<issuer_id>&<issuer_key_id>",
        data = "<proof>"
    )]
    pub async fn verify(
        proof: String,
        issuer_pk: String,
        verifying_keys: String,
        definition: String,
        issuer_id: String,
        issuer_key_id: String,
    ) -> Json<Value> {
        let mut rng = OsRng;

        let pres = zkp::Presentation::deserialize(&proof);

        let verifying_keys = {
            let bytes = BASE64_URL_SAFE_NO_PAD.decode(verifying_keys).unwrap();
            let str = String::from_utf8(bytes).unwrap();
            serde_json::from_str::<HashMap<String, String>>(&str).unwrap()
        };

        let reqs = {
            let bytes = BASE64_URL_SAFE_NO_PAD.decode(definition).unwrap();
            let str = String::from_utf8(bytes).unwrap();
            serde_json::from_str::<Vec<ProofRequirement>>(&str).unwrap()
        };

        // TODO: get device binding

        let json = zkp::verify(
            &mut rng,
            pres,
            issuer_pk,
            verifying_keys,
            &reqs,
            &issuer_id,
            &issuer_key_id,
            None,
        )
        .await;

        Json(json)
    }
}

#[get("/")]
fn index() -> String {
    format!("SPRIND Signing Service v{VERSION}")
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![index])
        .mount(
            "/fips204/44",
            routes![
                fips204_routes::Fips204MlDsa44Provider_gen_keypair,
                fips204_routes::Fips204MlDsa44Provider_sign,
                fips204_routes::Fips204MlDsa44Provider_verify
            ],
        )
        .mount(
            "/fips204/65",
            routes![
                fips204_routes::Fips204MlDsa65Provider_gen_keypair,
                fips204_routes::Fips204MlDsa65Provider_sign,
                fips204_routes::Fips204MlDsa65Provider_verify
            ],
        )
        .mount(
            "/fips204/87",
            routes![
                fips204_routes::Fips204MlDsa87Provider_gen_keypair,
                fips204_routes::Fips204MlDsa87Provider_sign,
                fips204_routes::Fips204MlDsa87Provider_verify
            ],
        )
        .mount(
            "/bbs+/g1/",
            routes![
                bbs_plus_routes::BbsPlusG1Provider_gen_keypair,
                bbs_plus_routes::BbsPlusG1Provider_sign,
                bbs_plus_routes::BbsPlusG1Provider_verify,
                bbs_plus_routes::BbsPlusG1Provider_create_pok_of_sig,
                bbs_plus_routes::BbsPlusG1Provider_verify_pok_of_sig,
            ],
        )
        .mount(
            "/bbs+/g2/",
            routes![
                bbs_plus_routes::BbsPlusG2Provider_gen_keypair,
                bbs_plus_routes::BbsPlusG2Provider_sign,
                bbs_plus_routes::BbsPlusG2Provider_verify,
            ],
        )
        .mount(
            "/zkp/",
            routes![
                zkp_routes::gen_keypair,
                zkp_routes::issue,
                zkp_routes::gen_proving_keys,
                zkp_routes::present,
                zkp_routes::verify
            ],
        )
}

#[cfg(test)]
mod test {
    use crate::VERSION;

    use super::*;
    use rocket::local::blocking::Client;
    use rocket::{http::Status, uri};

    macro_rules! test_roundtrip_fips204 {
        ($v:expr) => {
            paste::item! {
                #[test]
                fn [<test_roundtrip_fips204_ $v>]() {
                    use crate::KeyPair;
                    use next_gen_signatures::Engine;

                    let message = crate::BASE64_URL_SAFE_NO_PAD.encode("Hello, World!");

                    let client = Client::tracked(rocket()).expect("valid rocket instance");
                    let response = client
                        .get(format!(
                            "/fips204/{v}/keypair",
                            v = stringify!($v)
                        ))
                        .dispatch();
                    assert_eq!(response.status(), Status::Ok);

                    let keypair = response.into_json::<KeyPair>().unwrap();

                    let response = client
                        .get(format!(
                            "/fips204/{v}/sign?secret_key={sk}&message={msg}",
                            v = stringify!($v),
                            sk = keypair.secret_key,
                            msg = message,
                        ))
                        .dispatch();
                    assert_eq!(response.status(), Status::Ok);

                    let signature = response.into_json::<String>().unwrap();
                    let response = client
                        .get(format!(
                            "/fips204/{v}/verify?public_key={pk}&signature={sig}&message={msg}",
                            v = stringify!($v),
                            pk = keypair.public_key,
                            sig = signature,
                            msg = message,
                        ))
                        .dispatch();

                    assert_eq!(response.status(), Status::Ok);

                    let success = response.into_json::<bool>().unwrap();

                    assert!(success);
                }
            }
        };
    }

    macro_rules! test_roundtrip_bbs_plus {
        ($g:ident) => {
            paste::item! {
                #[test]
                fn [<test_roundtrip_bbs_plus_ $g>]() {
                    use next_gen_signatures::Engine;
                    use crate::KeyPair;

                    let nonce = next_gen_signatures::BASE64_URL_SAFE_NO_PAD.encode("nonce");
                    let message = next_gen_signatures::BASE64_URL_SAFE_NO_PAD.encode("Hello, World!");

                    let client = Client::tracked(rocket()).expect("valid rocket instance");
                    let response = client
                        .get(format!(
                            "/bbs+/{g}/keypair?nonce={n}&message_count={c}",
                            g = stringify!($g),
                            n = nonce,
                            c = 1
                        ))
                        .dispatch();
                    assert_eq!(response.status(), Status::Ok);

                    let keypair = response.into_json::<KeyPair>().unwrap();

                    let response = client
                        .get(format!(
                            "/bbs+/{g}/sign?secret_key={sk}&messages.0={msg}&nonce={n}&message_count={c}",
                            g = stringify!($g),
                            sk = keypair.secret_key,
                            msg = message,
                            n = nonce,
                            c = 1
                        ))
                        .dispatch();
                    assert_eq!(response.status(), Status::Ok);

                    let signature = response.into_json::<String>().unwrap();
                    let response = client
                        .get(format!(
                            "/bbs+/{g}/verify?public_key={pk}&signature={sig}&messages.0={msg}&nonce={n}&message_count={c}",
                            g = stringify!($g),
                            pk = keypair.public_key,
                            sig = signature,
                            msg = message,
                            n = nonce,
                            c = 1
                        ))
                        .dispatch();

                    assert_eq!(response.status(), Status::Ok);

                    let success = response.into_json::<bool>().unwrap();

                    assert!(success);
                }
            }
        };
    }

    #[test]
    fn index_should_contain_version() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client.get(uri!(super::index)).dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert!(response.into_string().unwrap().contains(VERSION));
    }

    test_roundtrip_fips204!(44);
    test_roundtrip_fips204!(65);
    test_roundtrip_fips204!(87);

    test_roundtrip_bbs_plus!(g1);
    test_roundtrip_bbs_plus!(g2);

    #[test]
    fn test_roundtrip_bbs_plus_g1_pok() {
        let nonce = BASE64_URL_SAFE_NO_PAD.encode("nonce");
        let messages = [
            b"message 1",
            b"message 2",
            b"message 3",
            b"message 4",
            b"message 5",
        ]
        .iter()
        .map(|m| BASE64_URL_SAFE_NO_PAD.encode(m))
        .collect::<Vec<_>>();

        let client = Client::tracked(rocket()).unwrap();
        let response = client
            .get(format!(
                "/bbs+/g1/keypair?nonce={n}&message_count={c}",
                n = nonce,
                c = messages.len()
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let keypair = response.into_json::<KeyPair>().unwrap();

        let response = client
            .get(format!(
                "/bbs+/g1/sign?secret_key={sk}&nonce={n}&message_count={c}&messages={msgs}",
                sk = keypair.secret_key,
                n = nonce,
                c = messages.len(),
                msgs = messages.join("&messages=")
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let signature = response.into_json::<String>().unwrap();

        let response = client
            .get(format!(
                "/bbs+/g1/pok/create?signature={signature}&nonce={nonce}&messages={msgs}&revealed_indexes={ri}",
                msgs = messages.join("&messages="),
                ri = ["0", "2", "4"].join("&revealed_indexes=")
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let proof = response.into_json::<String>().unwrap();

        let response = client
            .get(format!(
                "/bbs+/g1/pok/verify?proof={proof}{msgs}&public_key={pk}&nonce={nonce}&message_count={count}",
                msgs = [0usize, 2, 4]
                    .into_iter()
                    .map(|i| format!("&revealed_messages[{i}]={msg}", msg = &messages[i]))
                    .collect::<Vec<_>>().join(""),
                pk = &keypair.public_key,
                count = messages.len()
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let success = response.into_json::<bool>().unwrap();

        assert!(success);
    }
}
