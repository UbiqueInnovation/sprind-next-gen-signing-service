use rocket::{get, launch, routes, serde::json::Json};

use next_gen_signatures::{Engine, BASE64_URL_SAFE_NO_PAD};
use rocket_errors::anyhow;

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
    use super::*;
    use next_gen_signatures::generate_crypto_routes;

    generate_crypto_routes!(BbsPlusG1Provider);
    generate_crypto_routes!(BbsPlusG2Provider);
}

#[get("/")]
fn index() -> &'static str {
    "Hello, World!"
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
}

#[cfg(test)]
mod test {
    use super::rocket;
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
                            "/bbs+/{g}/sign?secret_key={sk}&message={msg}&nonce={n}&message_count={c}",
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
                            "/bbs+/{g}/verify?public_key={pk}&signature={sig}&message={msg}&nonce={n}&message_count={c}",
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
    fn hello_world() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client.get(uri!(super::index)).dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().unwrap(), "Hello, World!");
    }

    test_roundtrip_fips204!(44);
    test_roundtrip_fips204!(65);
    test_roundtrip_fips204!(87);

    test_roundtrip_bbs_plus!(g1);
    test_roundtrip_bbs_plus!(g2);
}
