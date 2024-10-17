use std::collections::BTreeMap;

use std::{collections::BTreeSet, io::Cursor};

use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::Engine;
use bbs_plus::prelude::{SignatureG1, SignatureParamsG1};
use blake2::Blake2b512;
use next_gen_signatures::{
    common::{ByteArray, CryptoProvider},
    crypto::{
        bbs::{GenParams, SignParams},
        BbsPlusG1Provider as Provider,
    },
    BASE64_URL_SAFE_NO_PAD,
};
use num_bigint::BigUint;
use proof_system::prelude::{
    bbs_plus::{PoKBBSSignatureG1Prover, PoKBBSSignatureG1Verifier},
    bound_check_legogroth16::{BoundCheckLegoGroth16Prover, BoundCheckLegoGroth16Verifier},
    generate_snark_srs_bound_check,
    r1cs_legogroth16::{ProvingKey, VerifyingKey},
    EqualWitnesses, MetaStatements, PoKBBSSignatureG1, Proof, ProofSpec, Statements, Witness,
    Witnesses,
};
use rand::{prelude::StdRng, RngCore, SeedableRng};

#[derive(Debug, Clone)]
pub enum ZkpProvable {
    BoundsCheck {
        signature_index: usize,
        message_index: usize,
        min: u64,
        max: u64,
    },
}

pub type ScalarField = Fr;
pub type Signature = SignatureG1<Bls12_381>;
pub type SignatureParams = SignatureParamsG1<Bls12_381>;
pub type StatementProver = PoKBBSSignatureG1Prover<Bls12_381>;
pub type BoundsStatementProver = BoundCheckLegoGroth16Prover<Bls12_381>;

#[allow(clippy::too_many_arguments)]
fn create_proof<R: RngCore>(
    rng: &mut R,
    signatures: Vec<Signature>,
    params: Vec<SignatureParams>,
    proving_key: ProvingKey<Bls12_381>,
    messages: Vec<String>,
    provables: Vec<ZkpProvable>,
    reveal_indexes: BTreeSet<u32>,
    proof_nonce: Option<String>,
) -> anyhow::Result<Proof<Bls12_381>> {
    let proof_nonce: Option<Vec<u8>> = match proof_nonce {
        None => None,
        Some(nonce) => Some(BASE64_URL_SAFE_NO_PAD.decode(nonce)?),
    };

    // TODO: some input sanity validation.

    let messages = messages
        .into_iter()
        .map(|m| BASE64_URL_SAFE_NO_PAD.decode(m))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|b| BigUint::from_bytes_le(&b).into())
        .collect::<Vec<Fr>>();

    let revealed_messages = messages
        .clone()
        .into_iter()
        .enumerate()
        //                                         ugly ↓
        .filter(|(idx, _)| reveal_indexes.contains(&(*idx as u32)))
        .collect::<BTreeMap<usize, Fr>>();

    let unrevealed_messages = messages
        .clone()
        .into_iter()
        .enumerate()
        //                                         ugly ↓
        .filter(|(idx, _)| !reveal_indexes.contains(&(*idx as u32)))
        .collect::<BTreeMap<usize, Fr>>();

    let proof_spec = {
        let mut statements = Statements::<Bls12_381>::new();

        let mut meta_statements = MetaStatements::new();

        for (idx, provable) in provables.clone().into_iter().enumerate() {
            match provable {
                ZkpProvable::BoundsCheck {
                    signature_index,
                    message_index,
                    min,
                    max,
                } => {
                    statements.add(StatementProver::new_statement_from_params(
                        params.get(signature_index).unwrap().clone(),
                        revealed_messages.clone(),
                    ));
                    statements.add(
                        BoundsStatementProver::new_statement_from_params(
                            min,
                            max,
                            proving_key.clone(),
                        )
                        .map_err(|err| anyhow::anyhow!("BoundsProver error: {err:?}"))?,
                    );

                    meta_statements.add_witness_equality(EqualWitnesses(BTreeSet::from([
                        (idx * 2, message_index),
                        (1, 0),
                    ])));
                }
            }
        }

        let proof_spec = ProofSpec::new(statements, meta_statements, vec![], None);
        proof_spec
            .validate()
            .map_err(|err| anyhow::anyhow!("ProofSpec validation error: {err:?}"))?;

        proof_spec
    };

    let witnesses = {
        let mut witnesses = Witnesses::new();

        for provable in provables.clone().into_iter() {
            match provable {
                ZkpProvable::BoundsCheck {
                    signature_index,
                    message_index,
                    ..
                } => {
                    witnesses.add(PoKBBSSignatureG1::new_as_witness(
                        signatures.get(signature_index).unwrap().clone(),
                        unrevealed_messages.clone(),
                    ));

                    witnesses.add(Witness::BoundCheckLegoGroth16(
                        messages.get(message_index).unwrap().clone(),
                    ));
                }
            }
        }

        witnesses
    };

    let (proof, _) =
        Proof::new::<R, Blake2b512>(rng, proof_spec, witnesses, proof_nonce, Default::default())
            .map_err(|err| anyhow::anyhow!("Failed to create proof: {err:?}"))?;

    Ok(proof)
}

#[allow(clippy::too_many_arguments)]
fn verify_proof(
    rng: &mut StdRng,
    proof: Proof<Bls12_381>,
    nonce: ByteArray,
    issuer_pk: ByteArray,
    verifying_key: VerifyingKey<Bls12_381>,
    message_count: u32,
    message_index: usize,
    min: u64,
    max: u64,
    revealed_messages: BTreeMap<usize, Fr>,
    proof_nonce: Option<String>,
) -> anyhow::Result<bool> {
    let issuer_pk = Provider::pk_from_bytes(issuer_pk)?;

    let proof_nonce: Option<Vec<u8>> = match proof_nonce {
        None => None,
        Some(nonce) => Some(BASE64_URL_SAFE_NO_PAD.decode(nonce)?),
    };

    let mut statements = Statements::<Bls12_381>::new();
    // Statement that the signature is correct
    statements.add(
        PoKBBSSignatureG1Verifier::<Bls12_381>::new_statement_from_params(
            SignatureParamsG1::new::<Blake2b512>(&nonce, message_count),
            issuer_pk,
            revealed_messages,
        ),
    );
    // Statement that the age is within bounds
    statements.add(
        BoundCheckLegoGroth16Verifier::new_statement_from_params(min, max, verifying_key)
            .map_err(|err| anyhow::anyhow!("{err:?}"))?,
    );

    let mut meta_statements = MetaStatements::new();
    // Meta-Statement that the witness is equal for both of the statements above
    // meaning that the above statements are "in the same context".
    meta_statements.add_witness_equality(EqualWitnesses(BTreeSet::from([
        // Witness of Statement 0 (valid sign) with message 0 (age)
        (0, message_index),
        // Witness of Statement 1 (wihthin bounds) with message 0
        (1, 0),
    ])));

    let proof_spec = ProofSpec::new(statements, meta_statements, vec![], None);
    proof_spec.validate().unwrap();

    proof
        .verify::<StdRng, Blake2b512>(rng, proof_spec, proof_nonce, Default::default())
        .map_err(|err| anyhow::anyhow!("Failed to verify proof: {err:?}"))?;

    Ok(true)
}

#[test]
pub fn zkp_sample() -> anyhow::Result<()> {
    let mut rng = StdRng::seed_from_u64(1337);
    // USE-CASE: We have 1 claim (message), that is our age
    // We want to create a ZKP that our age is >= 18, without
    // revealing our age.

    // Holder has an age
    let age = 21u64;

    let message_index = 1;

    // Verifier wants to know if holder min <= age < max
    let (min, max) = (18u64, 100u64);

    // Nonce, is publicy known
    let nonce_bytes = b"nonce";

    let proof_nonce = None;

    // ISSUANCE

    let revealed_indexes = BTreeSet::from([0, 2]);
    let revealed_messages = BTreeMap::from([
        (0, Fr::from(BigUint::from_bytes_le(b"message 1"))),
        (2, Fr::from(BigUint::from_bytes_le(b"message 2"))),
    ]);

    let (issuer_pk, signature, messages, message_count) = {
        let nonce = BASE64_URL_SAFE_NO_PAD.encode(nonce_bytes);

        let messages = vec![
            Fr::from(BigUint::from_bytes_le(b"message 1")),
            Fr::from(age),
            Fr::from(BigUint::from_bytes_le(b"message 2")),
            Fr::from(age),
        ];

        let message_count = messages.len() as u32;

        // issuer_sk is private, issuer_pk is publicly known
        let (issuer_pk, issuer_sk) = Provider::gen_keypair(GenParams {
            nonce: nonce.clone(),
            message_count,
        })?;

        // Created by Issuer
        let signature = {
            let messages = messages
                .iter()
                .map(|m| {
                    let b: BigUint = (*m).into();
                    BASE64_URL_SAFE_NO_PAD.encode(b.to_bytes_le())
                })
                .collect::<Vec<_>>();
            let sign_bytes = Provider::sign(
                &issuer_sk,
                SignParams {
                    nonce: nonce.clone(),
                    messages: messages.clone(),
                },
            )?;

            SignatureG1::<Bls12_381>::deserialize_compressed(Cursor::new(sign_bytes))?
        };

        (issuer_pk, signature, messages, message_count)
    };

    let verifier_pk = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng)
        .map_err(|err| anyhow::anyhow!("{err:?}"))?;

    let proof = {
        let mut signature_bytes = vec![];
        signature.serialize_compressed(&mut signature_bytes)?;

        let messages = messages
            .into_iter()
            .map(|m| {
                let b: BigUint = m.into();
                BASE64_URL_SAFE_NO_PAD.encode(b.to_bytes_le())
            })
            .collect::<Vec<_>>();

        create_proof(
            &mut rng,
            vec![signature],
            vec![SignatureParams::new::<Blake2b512>(
                nonce_bytes,
                message_count,
            )],
            verifier_pk.clone(),
            messages,
            vec![ZkpProvable::BoundsCheck {
                signature_index: 0,
                message_index,
                min,
                max,
            }],
            revealed_indexes,
            proof_nonce.clone(),
        )?
    };

    let success = verify_proof(
        &mut rng,
        proof,
        nonce_bytes.to_vec(),
        Provider::pk_into_bytes(issuer_pk.clone())?,
        verifier_pk.vk.clone(),
        message_count,
        message_index,
        min,
        max,
        revealed_messages,
        proof_nonce,
    )?;

    assert!(success);

    Ok(())
}
