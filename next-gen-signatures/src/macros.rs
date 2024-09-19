pub use paste;

#[macro_export]
macro_rules! test_provider {
    ($provider:ident) => {
        paste::item! {
            #[cfg(test)]
            #[allow(non_snake_case)]
            mod [<$provider _tests>] {
                use super::*;
                use $crate::common::CryptoProvider;

                #[test]
                fn test_pk_roundtrip() -> anyhow::Result<()> {
                    let (pk, _) = $provider::gen_keypair()?;
                    let bytes = $provider::pk_into_bytes(pk)?;
                    let pk2 = $provider::pk_from_bytes(bytes.clone())?;
                    let bytes2 = $provider::pk_into_bytes(pk2)?;

                    assert_eq!(bytes, bytes2);

                    Ok(())
                }

                #[test]
                fn test_sk_roundtrip() -> anyhow::Result<()> {
                    let (_, sk) = $provider::gen_keypair()?;
                    let bytes = $provider::sk_into_bytes(sk)?;
                    let sk2 = $provider::sk_from_bytes(bytes.clone())?;
                    let bytes2 = $provider::sk_into_bytes(sk2)?;

                    assert_eq!(bytes, bytes2);

                    Ok(())
                }

                #[test]
                fn test_sign_verify_roundtrip() -> anyhow::Result<()> {
                    let (pk, sk) = $provider::gen_keypair()?;

                    let msg = b"Hello, World".to_vec();
                    let sig = $provider::sign(&sk, msg.clone())?;
                    let valid = $provider::verify(&pk, msg, sig)?;

                    assert!(valid);

                    Ok(())
                }

            }
        }
    };
}

#[macro_export]
macro_rules! generate_crypto_routes {
    ($provider:ident) => {
        $crate::macros::paste::item! {
            #[get("/keypair")]
            #[allow(non_snake_case)]
            pub(crate) fn [<$provider _gen_keypair>]() -> Json<KeyPair> {
                let (pk, sk) = $crate::crypto::$provider::gen_keypair().unwrap();
                let pk = $crate::crypto::$provider::pk_into_bytes(pk).unwrap();
                let sk = $crate::crypto::$provider::sk_into_bytes(sk).unwrap();
                let pk = BASE64_URL_SAFE_NO_PAD.encode(pk);
                let sk = BASE64_URL_SAFE_NO_PAD.encode(sk);
                Json(KeyPair { public_key: pk, secret_key: sk })
            }

            #[get("/sign?<secret_key>&<message>")]
            #[allow(non_snake_case)]
            pub(crate) fn [<$provider _sign>](secret_key: &str, message: &str) -> Json<String> {
                let sk = BASE64_URL_SAFE_NO_PAD.decode(secret_key).unwrap();
                let sk = $crate::crypto::$provider::sk_from_bytes(sk).unwrap();
                let msg = BASE64_URL_SAFE_NO_PAD.decode(message).unwrap();

                let sig = $crate::crypto::$provider::sign(&sk, msg).unwrap();
                Json(BASE64_URL_SAFE_NO_PAD.encode(sig))
            }

            #[get("/verify?<public_key>&<message>&<signature>")]
            #[allow(non_snake_case)]
            pub(crate) fn [<$provider _verify>](public_key: &str, message: &str, signature: &str) -> Json<bool> {
                let pk = BASE64_URL_SAFE_NO_PAD.decode(public_key).unwrap();
                let pk = $crate::crypto::$provider::pk_from_bytes(pk).unwrap();
                let msg = BASE64_URL_SAFE_NO_PAD.decode(message).unwrap();
                let sig = BASE64_URL_SAFE_NO_PAD.decode(signature).unwrap();

                let valid = $crate::crypto::$provider::verify(&pk, msg, sig).unwrap();

                Json(valid)
            }
        }
    };
}
