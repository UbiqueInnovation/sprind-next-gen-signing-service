pub mod base64url {
    use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = BASE64_STANDARD_NO_PAD.encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        BASE64_STANDARD_NO_PAD
            .decode(base64.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}
