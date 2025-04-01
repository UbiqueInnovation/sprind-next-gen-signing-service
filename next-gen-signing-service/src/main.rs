use rocket::{get, launch, routes};

pub mod models;
pub mod routes;

const VERSION: &str = env!("CARGO_PKG_VERSION");

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
                routes::fips204::Fips204MlDsa44Provider_gen_keypair,
                routes::fips204::Fips204MlDsa44Provider_sign,
                routes::fips204::Fips204MlDsa44Provider_verify
            ],
        )
        .mount(
            "/fips204/65",
            routes![
                routes::fips204::Fips204MlDsa65Provider_gen_keypair,
                routes::fips204::Fips204MlDsa65Provider_sign,
                routes::fips204::Fips204MlDsa65Provider_verify
            ],
        )
        .mount(
            "/fips204/87",
            routes![
                routes::fips204::Fips204MlDsa87Provider_gen_keypair,
                routes::fips204::Fips204MlDsa87Provider_sign,
                routes::fips204::Fips204MlDsa87Provider_verify
            ],
        )
        .mount(
            "/bbs+/g1/",
            routes![
                routes::bbs_plus::BbsPlusG1Provider_gen_keypair,
                routes::bbs_plus::BbsPlusG1Provider_sign,
                routes::bbs_plus::BbsPlusG1Provider_verify,
                routes::bbs_plus::BbsPlusG1Provider_create_pok_of_sig,
                routes::bbs_plus::BbsPlusG1Provider_verify_pok_of_sig,
            ],
        )
        .mount(
            "/bbs+/g2/",
            routes![
                routes::bbs_plus::BbsPlusG2Provider_gen_keypair,
                routes::bbs_plus::BbsPlusG2Provider_sign,
                routes::bbs_plus::BbsPlusG2Provider_verify,
            ],
        )
        .mount(
            "/zkp/",
            routes![
                routes::zkp::gen_keypair,
                routes::zkp::issue,
                routes::zkp::gen_proving_keys,
                routes::zkp::present,
                routes::zkp::verify
            ],
        )
}

#[cfg(test)]
mod test {
    use crate::{models::common::KeyPair, VERSION};

    use super::*;
    use next_gen_signatures::{Engine, BASE64_URL_SAFE_NO_PAD};
    use rocket::local::blocking::Client;
    use rocket::{http::Status, uri};

    macro_rules! test_roundtrip_fips204 {
        ($v:expr) => {
            paste::item! {
                #[test]
                fn [<test_roundtrip_fips204_ $v>]() {
                    let message = BASE64_URL_SAFE_NO_PAD.encode("Hello, World!");

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
                    let nonce = BASE64_URL_SAFE_NO_PAD.encode("nonce");
                    let message = BASE64_URL_SAFE_NO_PAD.encode("Hello, World!");

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
