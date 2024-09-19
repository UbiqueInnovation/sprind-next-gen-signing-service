use rocket::{get, launch, routes, serde::json::Json};

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPair {
    pub public_key: String,
    pub secret_key: String,
}

mod fips204_routes {
    use super::*;
    use next_gen_signatures::common::CryptoProvider;
    use next_gen_signatures::generate_crypto_routes;
    use next_gen_signatures::{Engine, BASE64_URL_SAFE_NO_PAD};

    generate_crypto_routes!(Fips204MlDsa44Provider);
    generate_crypto_routes!(Fips204MlDsa65Provider);
    generate_crypto_routes!(Fips204MlDsa87Provider);
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
}

#[cfg(test)]
mod test {
    use super::rocket;
    use rocket::local::blocking::Client;
    use rocket::{http::Status, uri};

    #[test]
    fn hello_world() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client.get(uri!(super::index)).dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().unwrap(), "Hello, World!");
    }
}
