#[cfg(feature = "fips204")]
pub use fips204::*;

#[cfg(feature = "fips204")]
pub mod fips204 {
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

                fn pk_from_bytes(
                    bytes: crate::common::ByteArray,
                ) -> anyhow::Result<Self::PublicKey> {
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

                fn sk_from_bytes(
                    bytes: crate::common::ByteArray,
                ) -> anyhow::Result<Self::SecretKey> {
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
}

#[cfg(feature = "bbs")]
pub use bbs::*;

#[cfg(feature = "bbs")]
pub mod bbs {
    use std::io::Cursor;

    use crate::common::{ByteArray, CryptoProvider, TestDefault};
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use base64::Engine;
    use bbs_plus::prelude::{
        PublicKeyG1, PublicKeyG2, SecretKey, SignatureG1, SignatureG2, SignatureParamsG1,
        SignatureParamsG2,
    };
    use blake2::Blake2b512;
    use num_bigint::BigUint;
    use rand::RngCore;
    use rocket::FromForm;

    pub type Digest = Blake2b512;

    fn get_rng() -> impl RngCore {
        rand::rngs::OsRng
    }

    #[derive(FromForm)]
    pub struct GenParams {
        nonce: String,
        message_count: u32,
    }

    pub type SignParams = GenParams;

    pub type VerifyParams = SignParams;

    impl TestDefault for GenParams {
        fn default_for_test() -> Self {
            GenParams {
                nonce: crate::BASE64_URL_SAFE_NO_PAD.encode("nonce"),
                message_count: 1,
            }
        }
    }

    macro_rules! fix_arguments {
        (G1, $pk:expr, $params:expr) => {
            ($pk, $params)
        };
        (G2, $pk:expr, $params:expr) => {
            (&$pk, &$params)
        };
    }

    macro_rules! bbs_plus_provider_impl {
        ($g1:ident, $g2:ident, $pairing:ident) => {
            paste::item! {
                pub struct [<BbsPlus $g1 Provider>];

                impl CryptoProvider for [<BbsPlus $g1 Provider>] {
                    type GenParams = GenParams;
                    type SignParams = SignParams;
                    type VerifyParams = VerifyParams;

                    type PublicKey = [<PublicKey $g2>]<$pairing>;

                    type SecretKey = SecretKey<<$pairing as Pairing>::ScalarField>;

                    fn gen_keypair(
                        params: Self::GenParams,
                    ) -> anyhow::Result<(Self::PublicKey, Self::SecretKey)> {
                        let nonce = $crate::BASE64_URL_SAFE_NO_PAD.decode(&params.nonce)?;
                        let seed = {
                            let mut rng = get_rng();
                            let mut seed = ByteArray::new();
                            rng.fill_bytes(&mut seed);
                            seed
                        };

                        let params = [<SignatureParams $g1>]::<$pairing>::new::<Digest>(&nonce, params.message_count);

                        let sk = Self::SecretKey::generate_using_seed::<Digest>(&seed);
                        let pk = Self::PublicKey::generate_using_secret_key(&sk, &params);

                        Ok((pk, sk))
                    }

                    fn pk_into_bytes(pk: Self::PublicKey) -> anyhow::Result<crate::common::ByteArray> {
                        let mut bytes = ByteArray::new();
                        pk.serialize_compressed(&mut bytes)?;
                        Ok(bytes)
                    }

                    fn pk_from_bytes(bytes: crate::common::ByteArray) -> anyhow::Result<Self::PublicKey> {
                        Self::PublicKey::deserialize_compressed(Cursor::new(bytes)).map_err(|err| err.into())
                    }

                    fn sk_into_bytes(sk: Self::SecretKey) -> anyhow::Result<crate::common::ByteArray> {
                        let mut bytes = ByteArray::new();
                        sk.serialize_compressed(&mut bytes)?;
                        Ok(bytes)
                    }

                    fn sk_from_bytes(bytes: crate::common::ByteArray) -> anyhow::Result<Self::SecretKey> {
                        Self::SecretKey::deserialize_compressed(Cursor::new(bytes)).map_err(|err| err.into())
                    }

                    fn sign(
                        sk: &Self::SecretKey,
                        msg: crate::common::ByteArray,
                        params: Self::SignParams,
                    ) -> anyhow::Result<crate::common::ByteArray> {
                        let nonce = $crate::BASE64_URL_SAFE_NO_PAD.decode(&params.nonce)?;
                        let params = [<SignatureParams $g1>]::<$pairing>::new::<Digest>(&nonce, params.message_count);
                        let sig = [<Signature $g1>]::new(
                            &mut get_rng(),
                            &[BigUint::from_bytes_le(&msg).into()],
                            sk,
                            &params,
                        )
                        .map_err(|err| anyhow::anyhow!("Signature error: {:?}", err))?;
                        let mut bytes = ByteArray::new();
                        sig.serialize_compressed(&mut bytes)?;
                        Ok(bytes)
                    }

                    fn verify(
                        pk: Self::PublicKey,
                        msg: crate::common::ByteArray,
                        sig: crate::common::ByteArray,
                        params: Self::VerifyParams,
                    ) -> anyhow::Result<bool> {
                        let nonce = $crate::BASE64_URL_SAFE_NO_PAD.decode(&params.nonce)?;
                        let params = [<SignatureParams $g1>]::<$pairing>::new::<Digest>(&nonce, params.message_count);
                        let sig = [<Signature $g1>]::<$pairing>::deserialize_compressed(Cursor::new(sig))?;

                        let (pk, params) = fix_arguments!($g1, pk, params);

                        Ok(sig
                            .verify(
                                &[BigUint::from_bytes_le(&msg).into()],
                                pk,
                                params
                            )
                            .is_ok())
                    }
                }
            }
        };
    }

    bbs_plus_provider_impl!(G1, G2, Bls12_381);
    bbs_plus_provider_impl!(G2, G1, Bls12_381);

    #[cfg(test)]
    pub mod tests {
        use super::*;
        use crate::test_provider;

        test_provider!(BbsPlusG1Provider);
        test_provider!(BbsPlusG2Provider);
    }
}
