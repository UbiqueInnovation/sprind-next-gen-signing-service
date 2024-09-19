use anyhow::Result;

pub type ByteArray = Vec<u8>;

pub trait CryptoProvider {
    type PublicKey;
    type SecretKey;

    fn gen_keypair() -> Result<(Self::PublicKey, Self::SecretKey)>;

    fn pk_into_bytes(pk: Self::PublicKey) -> Result<ByteArray>;
    fn pk_from_bytes(bytes: ByteArray) -> Result<Self::PublicKey>;

    fn sk_into_bytes(sk: Self::SecretKey) -> Result<ByteArray>;
    fn sk_from_bytes(bytes: ByteArray) -> Result<Self::SecretKey>;

    fn sign(sk: &Self::SecretKey, msg: ByteArray) -> Result<ByteArray>;
    fn verify(pk: &Self::PublicKey, msg: ByteArray, sig: ByteArray) -> Result<bool>;
}

#[macro_export]
macro_rules! test_provider {
    ($provider:ident) => {
        paste::item! {
            #[cfg(test)]
            #[allow(non_snake_case)]
            mod [<$provider _test>] {
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
