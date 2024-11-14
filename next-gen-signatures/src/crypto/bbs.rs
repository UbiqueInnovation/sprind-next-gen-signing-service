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
use schnorr_pok::compute_random_oracle_challenge;

pub type Digest = Blake2b512;

fn get_rng() -> impl RngCore {
    rand::rngs::OsRng
}

#[cfg(feature = "rocket")]
use rocket::FromForm;

#[cfg(feature = "rocket")]
#[derive(FromForm)]
pub struct GenParams {
    pub nonce: String,
    pub message_count: u32,
}

#[cfg(not(feature = "rocket"))]
pub struct GenParams {
    pub nonce: String,
    pub message_count: u32,
}

#[cfg(feature = "rocket")]
#[derive(FromForm)]
pub struct SignParams {
    pub nonce: String,
    pub messages: Vec<String>,
}

#[cfg(not(feature = "rocket"))]
pub struct SignParams {
    pub nonce: String,
    pub messages: Vec<String>,
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

pub mod test {
    use std::{collections::HashMap, io::Cursor};

    use ark_bls12_381::Bls12_381;
    use legogroth16::circom::{r1cs::R1CSFile, CircomCircuit, R1CS as R1CSOrig};
    use multibase::Base;
    use oxrdf::GraphName;
    use rand::{prelude::StdRng, SeedableRng};
    use rdf_proofs::{
        ark_to_base64url, CircuitString, KeyGraph, KeyPairBase58Btc, VcPairString,
        VerifiableCredential,
    };

    use crate::rdf::RdfQuery;

    pub type R1CS = R1CSOrig<Bls12_381>;
    pub fn test_get_rng() -> StdRng {
        StdRng::seed_from_u64(1337)
    }

    pub fn test_get_keypair() -> KeyPairBase58Btc {
        let mut rng = test_get_rng();
        KeyPairBase58Btc::new(&mut rng).unwrap()
    }

    pub fn test_get_snark() -> (String, String) {
        let mut rng = test_get_rng();

        let circuit_r1cs = test_get_r1cs();
        let commit_witness_count = 1;
        let snark_proving_key = CircomCircuit::setup(circuit_r1cs.clone())
            .generate_proving_key(commit_witness_count, &mut rng)
            .unwrap();

        // serialize to multibase
        let snark_proving_key_string = ark_to_base64url(&snark_proving_key).unwrap();
        let snark_verifying_key_string = ark_to_base64url(&snark_proving_key.vk).unwrap();

        (snark_proving_key_string, snark_verifying_key_string)
    }

    pub fn test_get_r1cs() -> R1CS {
        let bytes = include_bytes!("../../circom/bls12381/less_than_public_64.r1cs");
        R1CSFile::new(Cursor::new(bytes)).unwrap().into()
    }

    const ISSUER_SECRET: &str = r#"
<did:example:issuer0> <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
<did:example:issuer0#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer0> .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "z489BikWV616m6F5ayUNDnLxWpHVmw3tG6hSgCVE9ZxDEXz3"^^<https://w3id.org/security#multibase> .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "zUC77roR12AzeB1bjwU6eK86NBBpJf5Rxvyqh8QcaEK6BxRTDoQucp2DSARoAABMWchDk4zxXmwfpHUeaWBg7T4q3Pne9YfnZBhStoGBmCzQcdj8pY3joRbr37w4TMcU1Pipqdp"^^<https://w3id.org/security#multibase> .
"#;

    const ISSUER_PUBLIC: &str = r#"
<did:example:issuer0> <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
<did:example:issuer0#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer0> .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "zUC77roR12AzeB1bjwU6eK86NBBpJf5Rxvyqh8QcaEK6BxRTDoQucp2DSARoAABMWchDk4zxXmwfpHUeaWBg7T4q3Pne9YfnZBhStoGBmCzQcdj8pY3joRbr37w4TMcU1Pipqdp"^^<https://w3id.org/security#multibase> .
"#;

    const VC: &str = r#"
<http://example.org/credentials/person/0> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/credentials/person/0> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
<http://example.org/credentials/person/0> <https://www.w3.org/2018/credentials#issuanceDate> "2024-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/credentials/person/0> <https://www.w3.org/2018/credentials#expirationDate> "2028-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/credentials/person/0> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:coolstuff> .
<did:example:coolstuff> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/CoolStuff> .
<did:example:coolstuff> <http://example.org/coolNumber> "1337"^^<http://www.w3.org/2001/XMLSchema#integer> .
<did:example:coolstuff> <http://example.org/coolString> "John Doe"^^<http://example.org/coolString> .
"#;

    const VC_HIDDEN: &str = r#"
<http://example.org/credentials/person/0> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/credentials/person/0> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
<http://example.org/credentials/person/0> <https://www.w3.org/2018/credentials#issuanceDate> "2024-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/credentials/person/0> <https://www.w3.org/2018/credentials#expirationDate> "2028-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/credentials/person/0> <https://www.w3.org/2018/credentials#credentialSubject> _:e0 .
_:e0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/CoolStuff> .
_:e0 <http://example.org/coolNumber> _:e1 .
_:e0 <http://example.org/coolString> "John Doe"^^<http://example.org/coolString> .
"#;

    const VC_PROOF_CFG: &str = r#"
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:b0 <http://purl.org/dc/terms/created> "2024-01-01T12:00:00.000Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
"#;

    pub async fn test_get_issuer() -> String {
        let issuer = test_get_keypair();
        let issuer_sk = issuer.secret_key;
        let issuer_pk = issuer.public_key;

        let issuer = RdfQuery::from_jsonld(
            &format!(
                r#"
            {{
                "@context": [
                    "https://www.w3.org/ns/controller/v1",
                    "https://w3id.org/security/data-integrity/v2"
                ],
                "id": "did:example:issuer0",
                "type": "Controller",
                "verificationMethod": {{
                    "id": "did:example:issuer0#bls12_381-g2-pub001",
                    "type": "Multikey",
                    "controller": "did:example:issuer0",
                    "secretKeyMultibase": "{issuer_sk}",
                    "publicKeyMultibase": "{issuer_pk}"
                }}
            }}"#
            ),
            Some("b".to_string()),
        )
        .await
        .unwrap();
        issuer.to_rdf_string()
    }

    pub fn test_issue() -> (String, String) {
        let mut rng = test_get_rng();

        let kg: KeyGraph = RdfQuery::new(ISSUER_SECRET)
            .unwrap()
            .as_graph(GraphName::DefaultGraph)
            .into();

        let mut vc = VerifiableCredential::new(
            RdfQuery::new(VC).unwrap().as_graph(GraphName::DefaultGraph),
            RdfQuery::new(VC_PROOF_CFG)
                .unwrap()
                .as_graph(GraphName::DefaultGraph),
        );
        rdf_proofs::sign(&mut rng, &mut vc, &kg).unwrap();

        (vc.document.to_string(), vc.proof.to_string())
    }

    pub fn test_present() -> String {
        let mut rng = test_get_rng();

        let vc_signed = r#"
<did:example:coolstuff> <http://example.org/coolString> "John Doe"^^<http://example.org/coolString> .
<did:example:coolstuff> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/CoolStuff> .
<did:example:coolstuff> <http://example.org/coolNumber> "1337"^^<http://www.w3.org/2001/XMLSchema#integer> .
<http://example.org/credentials/person/0> <https://www.w3.org/2018/credentials#issuanceDate> "2024-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/credentials/person/0> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/credentials/person/0> <https://www.w3.org/2018/credentials#expirationDate> "2028-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/credentials/person/0> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
<http://example.org/credentials/person/0> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:coolstuff> .
"#;
        let vc_proof_signed = r#"
_:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
_:b0 <http://purl.org/dc/terms/created> "2024-01-01T12:00:00.000Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:b0 <https://w3id.org/security#proofValue> "urmwROr8i6uMDe_2JSAKzV0oHFMUCob2lKfPG_zN3hYMuc84cfhyZaANSr85vl_B4nVbAf9v5-4CnD8HmtLIXh6R58ypeXPvhP0WuTe_Kf0n4hBOSPwmOXikaDEOzKGDcikDBg6sipzCdov-bUxsCTA"^^<https://w3id.org/security#multibase> .
"#;

        let deanon_map = HashMap::from([
            ("_:e0".to_string(), "<did:example:coolstuff>".to_string()),
            (
                "_:e1".to_string(),
                "\"1337\"^^<http://www.w3.org/2001/XMLSchema#integer>".to_string(),
            ),
        ]);

        let vc_pairs = vec![VcPairString::new(
            vc_signed,
            vc_proof_signed,
            VC_HIDDEN,
            VC_PROOF_CFG,
        )];

        // define circuit
        let circuit_r1cs = test_get_r1cs();
        let circuit_wasm = include_bytes!("../../circom/bls12381/less_than_public_64.wasm");

        // serialize to multibase
        let circuit_r1cs = ark_to_base64url(&circuit_r1cs).unwrap();
        let circuit_wasm = multibase::encode(Base::Base64Url, circuit_wasm);

        let (snark_proving_key_string, _) = test_get_snark();

        let predicates = vec![
r#"
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#Predicate> .
_:b0 <https://zkp-ld.org/security#circuit> <https://zkp-ld.org/circuit/alexey/lessThanPublic> .
_:b0 <https://zkp-ld.org/security#private> _:b1 .
_:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> _:b2 .
_:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#PrivateVariable> .
_:b2 <https://zkp-ld.org/security#var> "a" .
_:b2 <https://zkp-ld.org/security#val> _:e1 .
_:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil> .
_:b0 <https://zkp-ld.org/security#public> _:b3 .
_:b3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> _:b4 .
_:b4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#PublicVariable> .
_:b4 <https://zkp-ld.org/security#var> "b" .
_:b4 <https://zkp-ld.org/security#val> "9999"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:b3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil> .
"#.to_string(),
        ];

        let circuits = HashMap::from([(
            "https://zkp-ld.org/circuit/alexey/lessThanPublic".to_string(),
            CircuitString {
                circuit_r1cs,
                circuit_wasm,
                snark_proving_key: snark_proving_key_string,
            },
        )]);

        rdf_proofs::derive_proof_string(
            &mut rng,
            &vc_pairs,
            &deanon_map,
            ISSUER_PUBLIC,
            None,
            None,
            None,
            None,
            None,
            Some(&predicates),
            Some(&circuits),
        )
        .unwrap()
    }

    pub fn test_verify() {
        let mut rng = test_get_rng();

        let proof = r#"
<http://example.org/credentials/person/0> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n10 .
<http://example.org/credentials/person/0> <https://w3id.org/security#proof> _:c14n9 _:c14n10 .
<http://example.org/credentials/person/0> <https://www.w3.org/2018/credentials#credentialSubject> _:c14n5 _:c14n10 .
<http://example.org/credentials/person/0> <https://www.w3.org/2018/credentials#expirationDate> "2028-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n10 .
<http://example.org/credentials/person/0> <https://www.w3.org/2018/credentials#issuanceDate> "2024-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n10 .
<http://example.org/credentials/person/0> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> _:c14n10 .
_:c14n0 <http://purl.org/dc/terms/created> "2024-11-07T10:36:33.912496Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n11 .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n11 .
_:c14n0 <https://w3id.org/security#cryptosuite> "bbs-termwise-proof-2023" _:c14n11 .
_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#authenticationMethod> _:c14n11 .
_:c14n0 <https://w3id.org/security#proofValue> "uomFhWQN-AgAAAAAAAAAArKUTk0kCQOLNQw9nAPyeyxJAppgPXiJF7Xr7z9cCZ8EFL1ydqMmKlW358DDJ1_FOpUD5q0trrI3dNFgHxBoIDdi6aA5gnp9DRUltq8FkJsADriwz9fSKnjYvBZGwCjYPgLfYzOqY2vm1DS9tcZ8QoQuCucMkRRI-dwUuj3TLnuH39GVYxgB76lyJCfVumaQ9ruHBGkMW2L6F7dASV2QDzwhFPVG0yZHTI9XWiHV0VWr5V9DFF7Dq7GrW6A-XXcrUX6nbqIw5EFoPiB-kezPQP-z8vYiuD-VIio1ZtdRMsyhnR7pX-UDw-hk0F-3aAnWqQWkQ6HPYlmTOT2zK72cnWbCLUGwGpgaSbJs0XYkGx7w_3mkTRrcQhGoNXm-I_ZgWAlszH2l6vzqmdo720sIA7QABBQAAAAAAAAAAAAAAAAAAAMpVr-TyDpOTFWzxOwCGBVnmtGi5oU6fRjUlcwK0CJNIAQAAAAAAAACAfPYg9ap9Td-qcmSw0yRdrdaqflKYfnCWiZs_ZdiPUAUAAAAAAAAAUHSWZ2sXhJO0-he2HuaNHwYChPhPdx-ryMVzMk5FnGMKAAAAAAAAAFF9M3WpcD14lwLuFJ5tN-I7PSM7-dItCc_SgJdR5oUtCwAAAAAAAAAvbUf_pMmHjgrl3IM342r9bt6lD5qEFywjaAbjx4PNIQwAAAAAAAAABo8hdBPUj4mL_h4sc6Tamjgww81eXERlytfE1DucFQNAcSjAQTC9GOGe_5I-g5RE-rIbgGmMm_6nBiLYqT3UuDfMCZYVVwerq0hkGGrMhMpTt8-D15aAv_nMt5q5SXaLpxIIl3GLNH73bXLKmI6x24Mf9Gz5zi5_hDxhCdE9K-aVJWejOLQXZxLSzfzm_p6o-bUdiE5zs835KibotBv8Cr5dxFwL44mlmM2W6gNLJN5Fq6Q5Yqj3mwju7iEoQ60vKLDsSoXl7eBYa0w9x92pDTlfZOp_c5uD_zexAmis8OU3qQMcmVCgwnHKL3NDTOVxJJeHINvI6mDOXIYZAx_hKPaLAcMJBFJDIiYmWsr0T2Nv0T_NJ4I8dBI4SdSmAj40CwIAAAAAAAAAgHz2IPWqfU3fqnJksNMkXa3Wqn5SmH5wlombP2XYj1DFV05WtxG837tt_aDUqTX5hpj1Suqr8Za6CROmBfDwCwAAYWKBpGFhiAMEBQYHAAECYWIIYWOFAAECAwRhZAU"^^<https://w3id.org/security#multibase> _:c14n11 .
_:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiablePresentation> .
_:c14n1 <https://w3id.org/security#proof> _:c14n11 .
_:c14n1 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n10 .
_:c14n1 <https://zkp-ld.org/security#predicate> _:c14n13 .
_:c14n12 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> _:c14n2 _:c14n13 .
_:c14n12 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil> _:c14n13 .
_:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#PublicVariable> _:c14n13 .
_:c14n2 <https://zkp-ld.org/security#val> "9999"^^<http://www.w3.org/2001/XMLSchema#integer> _:c14n13 .
_:c14n2 <https://zkp-ld.org/security#var> "b" _:c14n13 .
_:c14n3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#PrivateVariable> _:c14n13 .
_:c14n3 <https://zkp-ld.org/security#val> _:c14n8 _:c14n13 .
_:c14n3 <https://zkp-ld.org/security#var> "a" _:c14n13 .
_:c14n4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> _:c14n3 _:c14n13 .
_:c14n4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil> _:c14n13 .
_:c14n5 <http://example.org/coolNumber> _:c14n8 _:c14n10 .
_:c14n5 <http://example.org/coolString> "John Doe"^^<http://example.org/coolString> _:c14n10 .
_:c14n5 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/CoolStuff> _:c14n10 .
_:c14n6 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#Predicate> _:c14n13 .
_:c14n6 <https://zkp-ld.org/security#circuit> <https://zkp-ld.org/circuit/alexey/lessThanPublic> _:c14n13 .
_:c14n6 <https://zkp-ld.org/security#private> _:c14n4 _:c14n13 .
_:c14n6 <https://zkp-ld.org/security#public> _:c14n12 _:c14n13 .
_:c14n7 <http://purl.org/dc/terms/created> "2024-01-01T12:00:00.000Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n9 .
_:c14n7 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n9 .
_:c14n7 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n9 .
_:c14n7 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n9 .
_:c14n7 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> _:c14n9 .
"#;

        let (_, snark_verifying_key_string) = test_get_snark();

        let snark_verifying_keys = HashMap::from([(
            "https://zkp-ld.org/circuit/alexey/lessThanPublic".to_string(),
            snark_verifying_key_string,
        )]);

        rdf_proofs::verify_proof_string(
            &mut rng,
            proof,
            ISSUER_PUBLIC,
            None,
            None,
            Some(snark_verifying_keys),
        )
        .unwrap();
    }

    #[tokio::test]
    pub async fn test_1() {
        test_issue();

        test_present();

        test_verify();
    }
}
