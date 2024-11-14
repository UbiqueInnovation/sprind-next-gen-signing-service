use base64::Engine;
use fips204::traits::{SerDes, Signer, Verifier};

#[cfg(feature = "rocket")]
use rocket::FromForm;

use crate::common::{CryptoProvider, NoArguments, TestDefault};

#[cfg(feature = "rocket")]
#[derive(FromForm)]
pub struct SignParams {
    message: String,
}

#[cfg(not(feature = "rocket"))]
pub struct SignParams {
    message: String,
}

impl TestDefault for SignParams {
    fn default_for_test() -> Self {
        Self {
            message: crate::BASE64_URL_SAFE_NO_PAD.encode(b"message"),
        }
    }
}

macro_rules! fips_provider_impl {
    ($provider_name:ident, $pkg_name:ident) => {
        pub struct $provider_name;
        impl CryptoProvider for $provider_name {
            type GenParams = NoArguments;
            type SignParams = SignParams;
            type VerifyParams = SignParams;

            type PublicKey = fips204::$pkg_name::PublicKey;

            type SecretKey = fips204::$pkg_name::PrivateKey;

            fn gen_keypair(
                _: Self::GenParams,
            ) -> anyhow::Result<(Self::PublicKey, Self::SecretKey)> {
                fips204::$pkg_name::try_keygen().map_err(|err| anyhow::anyhow!(err))
            }

            fn pk_into_bytes(pk: Self::PublicKey) -> anyhow::Result<crate::common::ByteArray> {
                Ok(pk.into_bytes().to_vec())
            }

            fn pk_from_bytes(bytes: crate::common::ByteArray) -> anyhow::Result<Self::PublicKey> {
                let bytes_len = bytes.len();
                Self::PublicKey::try_from_bytes(bytes.try_into().map_err(|_| {
                    anyhow::anyhow!(
                        "Expected an array of length {}, got {}!",
                        fips204::$pkg_name::PK_LEN,
                        bytes_len
                    )
                })?)
                .map_err(|err| anyhow::anyhow!(err))
            }

            fn sk_into_bytes(sk: Self::SecretKey) -> anyhow::Result<crate::common::ByteArray> {
                Ok(sk.into_bytes().to_vec())
            }

            fn sk_from_bytes(bytes: crate::common::ByteArray) -> anyhow::Result<Self::SecretKey> {
                let bytes_len = bytes.len();
                Self::SecretKey::try_from_bytes(bytes.try_into().map_err(|_| {
                    anyhow::anyhow!(
                        "Expected an array of length {}, got {}!",
                        fips204::$pkg_name::SK_LEN,
                        bytes_len
                    )
                })?)
                .map_err(|err| anyhow::anyhow!(err))
            }

            fn sign(
                sk: &Self::SecretKey,
                params: Self::SignParams,
            ) -> anyhow::Result<crate::common::ByteArray> {
                let msg = $crate::BASE64_URL_SAFE_NO_PAD.decode(&params.message)?;
                sk.try_sign(&msg)
                    .map(|res| res.to_vec())
                    .map_err(|err| anyhow::anyhow!(err))
            }

            fn verify(
                pk: Self::PublicKey,
                sig: crate::common::ByteArray,
                params: Self::VerifyParams,
            ) -> anyhow::Result<bool> {
                let msg = $crate::BASE64_URL_SAFE_NO_PAD.decode(&params.message)?;
                let sig_len = sig.len();
                let sig = sig.try_into().map_err(|_| {
                    anyhow::anyhow!(
                        "Expected a signature length of {}, got {}!",
                        fips204::$pkg_name::SIG_LEN,
                        sig_len
                    )
                })?;
                Ok(pk.verify(&msg, &sig))
            }
        }
    };
}

fips_provider_impl!(Fips204MlDsa44Provider, ml_dsa_44);
fips_provider_impl!(Fips204MlDsa65Provider, ml_dsa_65);
fips_provider_impl!(Fips204MlDsa87Provider, ml_dsa_87);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_provider;

    test_provider!(Fips204MlDsa44Provider);
    test_provider!(Fips204MlDsa65Provider);
    test_provider!(Fips204MlDsa87Provider);
}
