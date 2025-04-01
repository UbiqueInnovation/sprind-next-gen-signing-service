use rocket::{get, serde::json::Json};

use next_gen_signatures::generate_crypto_routes;
use next_gen_signatures::{Engine, BASE64_URL_SAFE_NO_PAD};
use rocket_errors::anyhow;

use crate::models::common::KeyPair;

generate_crypto_routes!(Fips204MlDsa44Provider);
generate_crypto_routes!(Fips204MlDsa65Provider);
generate_crypto_routes!(Fips204MlDsa87Provider);
