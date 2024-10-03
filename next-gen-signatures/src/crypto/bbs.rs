use std::{
    collections::{BTreeMap, BTreeSet},
    io::Cursor,
};

use crate::common::{ByteArray, CryptoProvider, TestDefault};
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::Engine;
use bbs_plus::prelude::{
    PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol, PublicKeyG1, PublicKeyG2, SecretKey,
    SignatureG1, SignatureG2, SignatureParamsG1, SignatureParamsG2,
};
use blake2::Blake2b512;
use dock_crypto_utils::signature::MessageOrBlinding;
use num_bigint::BigUint;
use rand::RngCore;
use rocket::FromForm;
use schnorr_pok::compute_random_oracle_challenge;

pub type Digest = Blake2b512;

fn get_rng() -> impl RngCore {
    rand::rngs::OsRng
}

#[derive(FromForm)]
pub struct GenParams {
    nonce: String,
    message_count: u32,
}

#[derive(FromForm)]
pub struct SignParams {
    nonce: String,
    messages: Vec<String>,
}

pub type VerifyParams = SignParams;

impl TestDefault for GenParams {
    fn default_for_test() -> Self {
        GenParams {
            nonce: crate::BASE64_URL_SAFE_NO_PAD.encode("nonce"),
            message_count: 4,
        }
    }
}

impl TestDefault for SignParams {
    fn default_for_test() -> Self {
        Self {
            nonce: crate::BASE64_URL_SAFE_NO_PAD.encode("nonce"),
            messages: vec![
                crate::BASE64_URL_SAFE_NO_PAD.encode(b"message 1"),
                crate::BASE64_URL_SAFE_NO_PAD.encode(b"message 2"),
                crate::BASE64_URL_SAFE_NO_PAD.encode(b"message 3"),
                crate::BASE64_URL_SAFE_NO_PAD.encode(b"message 4"),
            ],
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

macro_rules! bbs_plus_crypto_provider_impl {
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

                    fn pk_into_bytes(pk: Self::PublicKey) -> anyhow::Result<ByteArray> {
                        let mut bytes = ByteArray::new();
                        pk.serialize_compressed(&mut bytes)?;
                        Ok(bytes)
                    }

                    fn pk_from_bytes(bytes: ByteArray) -> anyhow::Result<Self::PublicKey> {
                        Self::PublicKey::deserialize_compressed(Cursor::new(bytes)).map_err(|err| err.into())
                    }

                    fn sk_into_bytes(sk: Self::SecretKey) -> anyhow::Result<ByteArray> {
                        let mut bytes = ByteArray::new();
                        sk.serialize_compressed(&mut bytes)?;
                        Ok(bytes)
                    }

                    fn sk_from_bytes(bytes: ByteArray) -> anyhow::Result<Self::SecretKey> {
                        Self::SecretKey::deserialize_compressed(Cursor::new(bytes)).map_err(|err| err.into())
                    }

                    fn sign(
                        sk: &Self::SecretKey,
                        params: Self::SignParams,
                    ) -> anyhow::Result<ByteArray> {
                        let nonce = $crate::BASE64_URL_SAFE_NO_PAD.decode(&params.nonce)?;
                        let messages: Vec<_> = params.messages.iter()
                            .map(|msg| $crate::BASE64_URL_SAFE_NO_PAD.decode(&msg))
                            .collect::<Result<Vec<_>, _>>()?
                            .iter()
                            .map(|msg| BigUint::from_bytes_le(msg).into()).collect();
                        let params = [<SignatureParams $g1>]::<$pairing>::new::<Digest>(&nonce, params.messages.len() as u32);
                        let sig = [<Signature $g1>]::new(
                            &mut get_rng(),
                            &messages,
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
                        sig: ByteArray,
                        params: Self::VerifyParams,
                    ) -> anyhow::Result<bool> {
                        let nonce = $crate::BASE64_URL_SAFE_NO_PAD.decode(&params.nonce)?;
                        let messages: Vec<_> = params.messages.iter()
                            .map(|msg| $crate::BASE64_URL_SAFE_NO_PAD.decode(&msg))
                            .collect::<Result<Vec<_>, _>>()?
                            .iter()
                            .map(|msg| BigUint::from_bytes_le(msg).into()).collect();
                        let params = [<SignatureParams $g1>]::<$pairing>::new::<Digest>(&nonce, params.messages.len() as u32);
                        let sig = [<Signature $g1>]::<$pairing>::deserialize_compressed(Cursor::new(sig))?;

                        let (pk, params) = fix_arguments!($g1, pk, params);

                        if !pk.is_valid() || !params.is_valid() {
                            anyhow::bail!("Invalid params!");
                        }

                        Ok(sig
                            .verify(
                                &messages,
                                pk,
                                params
                            )
                            .is_ok())
                    }
                }
            }
        };
    }

bbs_plus_crypto_provider_impl!(G1, G2, Bls12_381);
bbs_plus_crypto_provider_impl!(G2, G1, Bls12_381);

macro_rules! bbs_plus_provider_impl {
    ($g:ident) => {
        paste::item! {
            impl [<BbsPlus $g Provider>] {
                pub fn create_pok_of_sig(
                    sig: ByteArray,
                    msgs: Vec<String>,
                    nonce: String,
                    revealed_idxs: BTreeSet<usize>,
                ) -> anyhow::Result<ByteArray> {
                    type Fr = <Bls12_381 as Pairing>::ScalarField;

                    let nonce = crate::BASE64_URL_SAFE_NO_PAD.decode(nonce)?;

                    let params = [<SignatureParams $g>]::<Bls12_381>::new::<Digest>(&nonce, msgs.len() as u32);
                    let sig = [<Signature $g>]::deserialize_compressed(Cursor::new(sig))?;
                    let msgs: Vec<Fr> = msgs
                        .into_iter()
                        .map(|m| crate::BASE64_URL_SAFE_NO_PAD.decode(m))
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .map(|m| BigUint::from_bytes_le(&m).into())
                        .collect();

                    let mbi = (0..msgs.len())
                        .into_iter()
                        .map(|i| {
                            if revealed_idxs.contains(&i) {
                                MessageOrBlinding::RevealMessage(&msgs[i])
                            } else {
                                MessageOrBlinding::BlindMessageRandomly(&msgs[i])
                            }
                        })
                        .collect::<Vec<_>>();

                    let revealed_msgs = revealed_idxs
                        .into_iter()
                        .map(|i| (i, msgs[i]))
                        .collect::<BTreeMap<_, _>>();

                    let pok = [<PoKOfSignature $g Protocol>]::init(&mut get_rng(), &sig, &params, mbi)
                        .map_err(|err| anyhow::anyhow!("PoKOfSig Error: {:?}", err))?;

                    let mut chal_bytes_prover = vec![];
                    pok.challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_prover)
                        .map_err(|err| anyhow::anyhow!("Challenge Contribution error: {err:?}"))?;
                    let challenge_prover =
                        compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

                    let proof = pok
                        .gen_proof(&challenge_prover)
                        .map_err(|err| anyhow::anyhow!("Gen Proof error: {err:?}"))?;

                    let mut bytes = ByteArray::new();
                    proof.serialize_compressed(&mut bytes)?;

                    Ok(bytes)
                }

                pub fn verify_pok_of_sig(
                    proof: ByteArray,
                    revealed_msgs: BTreeMap<usize, String>,
                    public_key: <Self as CryptoProvider>::PublicKey,
                    nonce: String,
                    message_count: u32,
                ) -> anyhow::Result<bool> {
                    let nonce = crate::BASE64_URL_SAFE_NO_PAD.decode(nonce)?;
                    let params = [<SignatureParams $g>]::<Bls12_381>::new::<Digest>(&nonce, message_count);

                    let proof = [<PoKOfSignature $g Proof>]::<Bls12_381>::deserialize_compressed(Cursor::new(proof))?;

                    let revealed_msgs = revealed_msgs
                        .into_iter()
                        .map(|(k, v)| {
                            crate::BASE64_URL_SAFE_NO_PAD
                                .decode(v)
                                .and_then(|v| Ok((k, v)))
                        })
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .map(|(k, v)| (k, BigUint::from_bytes_le(&v).into()))
                        .collect();

                    let mut chal_bytes_verifier = vec![];
                    proof
                        .challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_verifier)
                        .unwrap();
                    let challenge_verifier = compute_random_oracle_challenge::<
                        <Bls12_381 as Pairing>::ScalarField,
                        Blake2b512,
                    >(&chal_bytes_verifier);

                    proof
                        .verify(&revealed_msgs, &challenge_verifier, public_key, params)
                        .map_err(|err| anyhow::anyhow!("Failed to verify: {err:?}"))?;

                    Ok(true)
                }
            }
        }
    };
}

// NOTE (pok-notes): Currently there is only a 'PoKOfSignatureG1Protocol'
// without a 'PoKOfSignatureG2Protocol' equivalent. Why that is, I honestly
// don't know.
bbs_plus_provider_impl!(G1);

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::test_provider;

    test_provider!(BbsPlusG1Provider);
    test_provider!(BbsPlusG2Provider);

    macro_rules! test_pok_of_sig {
        ($g:ident) => {
            paste::item! {
                #[test]
                #[allow(non_snake_case)]
                fn [<bbs_plus_ $g _provider_test_pok_of_sig>]() -> anyhow::Result<()> {
                    type Provider = [<BbsPlus $g Provider>];
                    let nonce = crate::BASE64_URL_SAFE_NO_PAD.encode(b"my-nonce");

                    let messages: Vec<String> = vec![b"msg1", b"msg2", b"msg3", b"msg4"]
                        .iter()
                        .map(|msg| crate::BASE64_URL_SAFE_NO_PAD.encode(msg))
                        .collect();

                    let params = GenParams {
                        nonce: nonce.clone(),
                        message_count: messages.len() as u32,
                    };

                    let (pk, sk) = Provider::gen_keypair(params)?;

                    let params = SignParams {
                        nonce: nonce.clone(),
                        messages: messages.clone(),
                    };

                    let sig = Provider::sign(&sk, params)?;

                    let proof = Provider::create_pok_of_sig(
                        sig,
                        messages.clone(),
                        nonce.clone(),
                        BTreeSet::from([0, 3]),
                    )?;

                    let success = Provider::verify_pok_of_sig(
                        proof,
                        BTreeMap::from([(0, messages[0].clone()), (3, messages[3].clone())]),
                        pk,
                        nonce.clone(),
                        messages.len() as u32,
                    )?;

                    assert!(success);

                    Ok(())
                }
            }
        };
    }

    // NOTE: Why only G1 see above (pok-notes)
    test_pok_of_sig!(G1);
}
