pub use paste;

#[macro_export]
macro_rules! test_provider {
    ($provider:ident) => {
        paste::item! {
            #[cfg(test)]
            #[allow(non_snake_case)]
            mod [<$provider _tests>] {
                use super::*;
                use $crate::common::{CryptoProvider, TestDefault};

                #[test]
                fn test_pk_roundtrip() -> anyhow::Result<()> {
                    let (pk, _) = $provider::gen_keypair(<$provider as CryptoProvider>::GenParams::default_for_test())?;
                    let bytes = $provider::pk_into_bytes(pk)?;
                    let pk2 = $provider::pk_from_bytes(bytes.clone())?;
                    let bytes2 = $provider::pk_into_bytes(pk2)?;

                    assert_eq!(bytes, bytes2);

                    Ok(())
                }

                #[test]
                fn test_sk_roundtrip() -> anyhow::Result<()> {
                    let (_, sk) = $provider::gen_keypair(<$provider as CryptoProvider>::GenParams::default_for_test())?;
                    let bytes = $provider::sk_into_bytes(sk)?;
                    let sk2 = $provider::sk_from_bytes(bytes.clone())?;
                    let bytes2 = $provider::sk_into_bytes(sk2)?;

                    assert_eq!(bytes, bytes2);

                    Ok(())
                }

                #[test]
                fn test_sign_verify_roundtrip() -> anyhow::Result<()> {
                    let (pk, sk) = $provider::gen_keypair(<$provider as CryptoProvider>::GenParams::default_for_test())?;

                    let sig = $provider::sign(
                        &sk,
                        <$provider as CryptoProvider>::SignParams::default_for_test()
                    )?;
                    let valid = $provider::verify(
                        pk,
                        sig,
                        <$provider as CryptoProvider>::VerifyParams::default_for_test()
                    )?;

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
            #[get("/keypair?<params..>")]
            #[allow(non_snake_case)]
            pub(crate) fn [<$provider _gen_keypair>](
                params: <$crate::crypto::$provider as $crate::common::CryptoProvider>::GenParams
            ) -> anyhow::Result<Json<KeyPair>> {
                use next_gen_signatures::common::CryptoProvider;

                let (pk, sk) = $crate::crypto::$provider::gen_keypair(params)?;
                let pk = $crate::crypto::$provider::pk_into_bytes(pk)?;
                let sk = $crate::crypto::$provider::sk_into_bytes(sk)?;
                let pk = BASE64_URL_SAFE_NO_PAD.encode(pk);
                let sk = BASE64_URL_SAFE_NO_PAD.encode(sk);
                Ok(Json(KeyPair { public_key: pk, secret_key: sk }))
            }

            #[get("/sign?<secret_key>&<params..>")]
            #[allow(non_snake_case)]
            pub(crate) fn [<$provider _sign>](
                secret_key: &str,
                params: <$crate::crypto::$provider as $crate::common::CryptoProvider>::SignParams
            ) -> anyhow::Result<Json<String>> {
                use next_gen_signatures::common::CryptoProvider;

                let sk = BASE64_URL_SAFE_NO_PAD.decode(secret_key).unwrap();
                let sk = $crate::crypto::$provider::sk_from_bytes(sk).unwrap();

                let sig = $crate::crypto::$provider::sign(&sk, params).unwrap();
                Ok(Json(BASE64_URL_SAFE_NO_PAD.encode(sig)))
            }

            #[get("/verify?<public_key>&<signature>&<params..>")]
            #[allow(non_snake_case)]
            pub(crate) fn [<$provider _verify>](
                public_key: &str,
                signature: &str,
                params: <$crate::crypto::$provider as $crate::common::CryptoProvider>::VerifyParams
            ) -> Json<bool> {
                use next_gen_signatures::common::CryptoProvider;

                let pk = BASE64_URL_SAFE_NO_PAD.decode(public_key).unwrap();
                let pk = $crate::crypto::$provider::pk_from_bytes(pk).unwrap();
                let sig = BASE64_URL_SAFE_NO_PAD.decode(signature).unwrap();

                let valid = $crate::crypto::$provider::verify(pk, sig, params).unwrap();

                Json(valid)
            }
        }
    };
}
