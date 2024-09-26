use fips204::traits::{SerDes, Signer, Verifier};

use crate::common::{CryptoProvider, NoArguments};

macro_rules! fips_provider_impl {
    ($provider_name:ident, $pkg_name:ident) => {
        pub struct $provider_name;
        impl CryptoProvider for $provider_name {
            type GenParams = NoArguments;
            type SignParams = NoArguments;
            type VerifyParams = NoArguments;

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
                msg: crate::common::ByteArray,
                _: Self::SignParams,
            ) -> anyhow::Result<crate::common::ByteArray> {
                sk.try_sign(&msg)
                    .map(|res| res.to_vec())
                    .map_err(|err| anyhow::anyhow!(err))
            }

            fn verify(
                pk: Self::PublicKey,
                msg: crate::common::ByteArray,
                sig: crate::common::ByteArray,
                _: Self::VerifyParams,
            ) -> anyhow::Result<bool> {
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
