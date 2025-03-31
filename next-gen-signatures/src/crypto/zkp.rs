use std::{collections::HashMap, fmt::Write, io::Cursor, str::FromStr};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use chrono::DateTime;
use fips204::RngCore;
use json_ld::{
    rdf_types::generator, syntax::Parse, JsonLdProcessor, RemoteDocument, ReqwestLoader,
};
use num_bigint::BigUint;
use rdf_util::Value as RdfValue;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use static_iref::iri;
use zkp_util::{
    device_binding::{SecpAffine, SecpFr},
    vc::{
        requirements::{DeviceBindingRequirement, ProofRequirement},
        VerifiableCredential,
    },
    EcdsaSignature,
};

pub use zkp_util::keypair::generate_keypair;

async fn parse_json_ld(data: &str) -> anyhow::Result<RdfValue> {
    let doc = RemoteDocument::new(None, None, json_ld::syntax::Value::parse_str(data)?.0);

    let mut loader = json_ld::FsLoader::default();
    loader.mount(iri!("https://www.w3.org/").to_owned(), "jsonld");
    loader.mount(iri!("https://w3id.org/").to_owned(), "jsonld");
    loader.mount(iri!("http://schema.org/").to_owned(), "jsonld");

    let loader = json_ld::loader::ChainLoader::new(loader, ReqwestLoader::new());

    let mut generator = generator::Blank::new_with_prefix("b".to_string());
    let mut rdf = doc.to_rdf(&mut generator, &loader).await?;

    let rdf = rdf.cloned_quads().fold(String::new(), |mut output, q| {
        let _ = writeln!(output, "{q} .");
        output
    });

    rdf_util::from_str(rdf).map_err(|e| e.into())
}

pub async fn issue<R: RngCore>(
    rng: &mut R,
    claims: JsonValue,
    issuer_pk: &str,
    issuer_sk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
    issuance_date: Option<&str>,
    created_date: Option<&str>,
    expiration_date: Option<&str>,
    device_binding: Option<(String, String)>,
) -> anyhow::Result<String> {
    let claims = parse_json_ld(&claims.to_string()).await?;

    let issuance_date = issuance_date.map(|d| DateTime::from_str(d)).transpose()?;
    let created_date = created_date.map(|d| DateTime::from_str(d)).transpose()?;
    let expiration_date = expiration_date.map(|d| DateTime::from_str(d)).transpose()?;

    let vc = zkp_util::vc::issuance::issue(
        rng,
        claims,
        issuer_pk,
        issuer_sk,
        issuer_id,
        issuer_key_id,
        issuance_date,
        created_date,
        expiration_date,
        device_binding,
    )?;

    let credential = BASE64_URL_SAFE_NO_PAD.encode(
        json!({
            "document": BASE64_URL_SAFE_NO_PAD.encode(vc.document.to_string()),
            "proof": BASE64_URL_SAFE_NO_PAD.encode(vc.proof.to_string())
        })
        .to_string(),
    );

    Ok(credential)
}

pub use zkp_util::circuits::generate_circuits;

#[derive(Debug, Serialize, Deserialize)]
pub struct DBRequirement {
    #[serde(with = "base64url")]
    pub public_key: Vec<u8>,

    #[serde(with = "base64url")]
    pub message: Vec<u8>,

    #[serde(with = "base64url")]
    pub message_signature_rand_x_coord: Vec<u8>,

    #[serde(with = "base64url")]
    pub message_signature_response: Vec<u8>,

    #[serde(with = "base64url")]
    pub comm_key_secp_label: Vec<u8>,

    #[serde(with = "base64url")]
    pub comm_key_tom_label: Vec<u8>,

    #[serde(with = "base64url")]
    pub comm_key_bls_label: Vec<u8>,

    #[serde(with = "base64url")]
    pub bpp_setup_label: Vec<u8>,

    #[serde(with = "base64url")]
    pub merlin_transcript_label: Vec<u8>,

    #[serde(with = "base64url")]
    pub challenge_label: Vec<u8>,
}

mod base64url {
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
            .map_err(|e| serde::de::Error::custom(e))
    }
}

pub fn present<R: RngCore>(
    rng: &mut R,
    vc: String,
    requirements: &Vec<ProofRequirement>,
    device_binding: Option<DBRequirement>,
    proving_keys: &HashMap<String, String>,
    issuer_pk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
) -> anyhow::Result<String> {
    let vc = {
        let json = serde_json::from_str::<JsonValue>(&String::from_utf8(
            BASE64_URL_SAFE_NO_PAD.decode(&vc)?,
        )?)?;

        let document = rdf_util::from_str(String::from_utf8(
            BASE64_URL_SAFE_NO_PAD.decode(json["document"].as_str().unwrap())?,
        )?)?;

        let proof = rdf_util::from_str(String::from_utf8(
            BASE64_URL_SAFE_NO_PAD.decode(json["proof"].as_str().unwrap())?,
        )?)?;

        VerifiableCredential {
            document: document.to_graph(None),
            proof: proof.to_graph(None),
        }
    };

    let device_binding = if let Some(db) = device_binding {
        Some(DeviceBindingRequirement {
            public_key: SecpAffine::deserialize_uncompressed(Cursor::new(db.public_key))?,
            message: SecpFr::from(BigUint::from_bytes_be(&db.message)),
            message_signature: EcdsaSignature {
                rand_x_coord: SecpFr::from(BigUint::from_bytes_be(
                    &db.message_signature_rand_x_coord,
                )),
                response: SecpFr::from(BigUint::from_bytes_be(&db.message_signature_response)),
            },
            comm_key_secp_label: db.comm_key_secp_label,
            comm_key_tom_label: db.comm_key_tom_label,
            comm_key_bls_label: db.comm_key_bls_label,
            bpp_setup_label: db.bpp_setup_label,
            merlin_transcript_label: Box::leak(Box::new(db.merlin_transcript_label)),
            challenge_label: Box::leak(Box::new(db.challenge_label)),
        })
    } else {
        None
    };

    let vp = zkp_util::vc::presentation::present(
        rng,
        vc,
        requirements,
        device_binding,
        proving_keys,
        issuer_pk,
        issuer_id,
        issuer_key_id,
    )?;

    let db = if let Some(db) = vp.device_binding {
        let mut bytes = Vec::<u8>::new();
        db.serialize_compressed(&mut bytes)?;
        Some(BASE64_URL_SAFE_NO_PAD.encode(bytes))
    } else {
        None
    };

    let token = BASE64_URL_SAFE_NO_PAD.encode(
        json!({
            "proof": BASE64_URL_SAFE_NO_PAD.encode(vp.proof.dataset().to_string()),
            "device_binding": db
        })
        .to_string(),
    );

    Ok(token)
}

pub fn verify() {}
