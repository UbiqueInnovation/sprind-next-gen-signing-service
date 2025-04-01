#[derive(Debug, rocket::serde::Serialize, rocket::serde::Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct KeyPair {
    pub public_key: String,
    pub secret_key: String,
}

pub mod encodings {
    pub mod base64url {
        use next_gen_signatures::{Engine, BASE64_URL_SAFE_NO_PAD};
        use rocket::serde;
        use serde::{Deserialize, Serialize};
        use serde::{Deserializer, Serializer};

        pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
            let base64 = BASE64_URL_SAFE_NO_PAD.encode(v);
            String::serialize(&base64, s)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
            let base64 = String::deserialize(d)?;
            BASE64_URL_SAFE_NO_PAD
                .decode(base64.as_bytes())
                .map_err(serde::de::Error::custom)
        }
    }
}
