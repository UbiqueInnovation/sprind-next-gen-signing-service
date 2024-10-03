use std::{
    collections::{BTreeMap, BTreeSet},
    io::Cursor,
};

use anyhow::{ensure, Context};
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
    r1cs_legogroth16::ProvingKey,
    EqualWitnesses, MetaStatements, PoKBBSSignatureG1, Proof, ProofSpec, Statements, Witness,
    Witnesses,
};
use rand::{prelude::StdRng, RngCore, SeedableRng};

fn create_bounds_proof<R: RngCore>(
    rng: &mut R,
    signature: ByteArray,
    nonce: String,
    proving_key: ProvingKey<Bls12_381>,
    messages: Vec<String>,
    message_index: usize,
    min: u64,
    max: u64,
    reveal_indexes: BTreeSet<u32>,
    proof_nonce: Option<String>,
) -> anyhow::Result<Proof<Bls12_381>> {
    type Signature = SignatureG1<Bls12_381>;
    type SignatureParams = SignatureParamsG1<Bls12_381>;
    type StatementProver = PoKBBSSignatureG1Prover<Bls12_381>;
    type BoundsStatementProver = BoundCheckLegoGroth16Prover<Bls12_381>;

    let signature = Signature::deserialize_compressed(Cursor::new(signature))?;

    let nonce = BASE64_URL_SAFE_NO_PAD.decode(nonce)?;
    let proof_nonce: Option<Vec<u8>> = match proof_nonce {
        None => None,
        Some(nonce) => Some(BASE64_URL_SAFE_NO_PAD.decode(nonce)?),
    };

    fn parse_messages(messages: Vec<String>) -> anyhow::Result<Vec<Fr>> {
        Ok(messages
            .into_iter()
            .map(|m| BASE64_URL_SAFE_NO_PAD.decode(m))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|b| BigUint::from_bytes_le(&b).into())
            .collect())
    }

    let message_count = messages.len() as u32;

    let message = Fr::from(BigUint::from_bytes_le(
        &BASE64_URL_SAFE_NO_PAD.decode(
            messages
                .get(message_index)
                .context("message_index out of bounds!")?,
        )?,
    ));

    let messages_clone = parse_messages(messages.clone())?;
    let messages = parse_messages(messages.clone())?;

    let params = SignatureParams::new::<Blake2b512>(&nonce, message_count);

    ensure!(min < max, "min < max not satisfied!");

    ensure!(
        (reveal_indexes.len() as u32) < message_count,
        "|revealed| < |messages| not satisfied!"
    );

    reveal_indexes
        .iter()
        .map(|idx| {
            if *idx == message_index as u32 {
                Err(anyhow::anyhow!("Can't reveal message_index"))
            } else if *idx >= message_count {
                Err(anyhow::anyhow!("revealed index out of bounds: {idx}"))
            } else {
                Ok(())
            }
        })
        .collect::<Result<(), _>>()?;

    let proof_spec = {
        let mut statements = Statements::<Bls12_381>::new();
        statements.add(StatementProver::new_statement_from_params(
            params,
            messages
                .into_iter()
                .enumerate()
                //                                         ugly ↓
                .filter(|(idx, _)| reveal_indexes.contains(&(*idx as u32)))
                .collect(),
        ));
        statements.add(
            BoundsStatementProver::new_statement_from_params(min, max, proving_key)
                .map_err(|err| anyhow::anyhow!("BoundsProver error: {err:?}"))?,
        );

        let mut meta_statements = MetaStatements::new();
        meta_statements
            .add_witness_equality(EqualWitnesses(BTreeSet::from([(0, message_index), (1, 0)])));

        let proof_spec = ProofSpec::new(statements, meta_statements, vec![], None);
        proof_spec
            .validate()
            .map_err(|err| anyhow::anyhow!("ProofSpec validation error: {err:?}"))?;

        proof_spec
    };

    let witnesses = {
        let mut witnesses = Witnesses::new();

        // Witness for the signature
        witnesses.add(PoKBBSSignatureG1::new_as_witness(
            signature,
            // ugly: why is Fr not clone :/
            messages_clone
                .into_iter()
                .enumerate()
                //                                          ugly ↓
                .filter(|(idx, _)| !reveal_indexes.contains(&(*idx as u32)))
                .collect(),
        ));
        // Witness for the bounds check
        witnesses.add(Witness::BoundCheckLegoGroth16(message));

        witnesses
    };

    let (proof, _) =
        Proof::new::<R, Blake2b512>(rng, proof_spec, witnesses, proof_nonce, Default::default())
            .map_err(|err| anyhow::anyhow!("Failed to create proof: {err:?}"))?;

    Ok(proof)
}

#[test]
pub fn bbs_plus_bounds_check() -> anyhow::Result<()> {
    let mut rng = StdRng::seed_from_u64(1337);
    // USE-CASE: We have 1 claim (message), that is our age
    // We want to create a ZKP that our age is >= 18, without
    // revealing our age.

    // Holder has an age
    let age = 21u64;

    // Verifier wants to know if holder min <= age < max
    let (min, max) = (18u64, 100u64);

    // Nonce, is publicy known
    let nonce_bytes = b"nonce";

    // ISSUANCE

    let (issuer_pk, signature, messages, message_count) = {
        let nonce = BASE64_URL_SAFE_NO_PAD.encode(&nonce_bytes);

        let messages = vec![Fr::from(age)];
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
                    let b: BigUint = m.clone().into();
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

    // VERIFIER

    // Verifier sets up LegoGroth16 public parameters for bound check circuit. Ideally this should be
    // done only once per verifier and can be published by the verifier for any proofs submitted to him.
    let verifier_pk = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng)
        .map_err(|err| anyhow::anyhow!("{err:?}"))?;

    // PROVER (HOLDER)
    /*
    let proof = {
        let mut statements = Statements::<Bls12_381>::new();
        // Statement that the signature is correct
        statements.add(PoKBBSSignatureG1Prover::new_statement_from_params(
            SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(nonce_bytes, message_count),
            BTreeMap::from([]),
        ));
        // Statement that the age is within bounds
        statements.add(
            BoundCheckLegoGroth16Prover::new_statement_from_params(min, max, verifier_pk.clone())
                .map_err(|err| anyhow::anyhow!("{err:?}"))?,
        );

        let mut meta_statements = MetaStatements::new();
        // Meta-Statement that the witness is equal for both of the statements above
        // meaning that the above statements are "in the same context".
        meta_statements.add_witness_equality(EqualWitnesses(BTreeSet::from([
            // Witness of Statement 0 (valid sign) with message 0 (age)
            (0, 0),
            // Witness of Statement 1 (wihthin bounds) with message 0
            (1, 0),
        ])));

        let mut witnesses = Witnesses::new();
        // Witness for the signature
        witnesses.add(PoKBBSSignatureG1::new_as_witness(
            signature,
            messages.into_iter().enumerate().collect(),
        ));
        // Witness for the bounds check
        witnesses.add(Witness::BoundCheckLegoGroth16(Fr::from(age)));

        let proof_spec = ProofSpec::new(statements, meta_statements, vec![], None);
        proof_spec.validate().unwrap();

        let (proof, _) = Proof::new::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec,
            witnesses,
            None,
            Default::default(),
        )
        .map_err(|err| anyhow::anyhow!("{err:?}"))?;

        proof
    };
    */
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

        let proof = create_bounds_proof(
            &mut rng,
            signature_bytes,
            BASE64_URL_SAFE_NO_PAD.encode(nonce_bytes),
            verifier_pk.clone(),
            messages,
            0,
            min,
            max,
            BTreeSet::from([]),
            None,
        )?;

        proof
    };

    let result = {
        let mut statements = Statements::<Bls12_381>::new();
        // Statement that the signature is correct
        statements.add(
            PoKBBSSignatureG1Verifier::<Bls12_381>::new_statement_from_params(
                SignatureParamsG1::new::<Blake2b512>(nonce_bytes, message_count),
                issuer_pk,
                BTreeMap::from([]),
            ),
        );
        // Statement that the age is within bounds
        statements.add(
            BoundCheckLegoGroth16Verifier::new_statement_from_params(min, max, verifier_pk.vk)
                .map_err(|err| anyhow::anyhow!("{err:?}"))?,
        );

        let mut meta_statements = MetaStatements::new();
        // Meta-Statement that the witness is equal for both of the statements above
        // meaning that the above statements are "in the same context".
        meta_statements.add_witness_equality(EqualWitnesses(BTreeSet::from([
            // Witness of Statement 0 (valid sign) with message 0 (age)
            (0, 0),
            // Witness of Statement 1 (wihthin bounds) with message 0
            (1, 0),
        ])));

        let proof_spec = ProofSpec::new(statements, meta_statements, vec![], None);
        proof_spec.validate().unwrap();

        proof.verify::<StdRng, Blake2b512>(&mut rng, proof_spec, None, Default::default())
    };

    result.unwrap();

    Ok(())
}
