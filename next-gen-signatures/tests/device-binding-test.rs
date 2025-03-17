use std::collections::BTreeMap;

use std::{collections::BTreeSet, io::Cursor};

use ark_bls12_381::{Bls12_381, Fr, G1Projective};
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
use p256::ecdsa::SigningKey;
use proof_system::prelude::{
    bbs_plus::{PoKBBSSignatureG1Prover, PoKBBSSignatureG1Verifier},
    bound_check_legogroth16::BoundCheckLegoGroth16Prover,
    ped_comm::PedersenCommitment,
    EqualWitnesses, MetaStatements, PoKBBSSignatureG1, Proof, ProofSpec, Statements, Witness,
    Witnesses,
};
use proves::dleq::PairingPedersenParams;
use proves::{device_binding, p256_arithmetic, tom256, DeviceBinding};
use rand::rngs::OsRng;
use rand::{prelude::StdRng, RngCore, SeedableRng};

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_std::UniformRand;
use proves::group::Group;

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
    messages: Vec<String>,
    reveal_indexes: BTreeSet<u32>,
    proof_nonce: Option<String>,
    signing_key: SigningKey,
    public_key: Vec<u8>,
    binding_string: String,
) -> anyhow::Result<(
    Proof<Bls12_381>,
    DeviceBinding<
        proves::p256_arithmetic::ProjectivePoint,
        32,
        proves::tom256::ProjectivePoint,
        40,
        Bls12_381,
    >,
)> {
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

    let bases_x = (0..2)
        .map(|_| G1Projective::rand(&mut OsRng).into_affine())
        .collect::<Vec<_>>();
    let bases_y = (0..2)
        .map(|_| G1Projective::rand(&mut OsRng).into_affine())
        .collect::<Vec<_>>();
    let scalars_x = vec![messages[0], ScalarField::rand(&mut OsRng)];
    let scalars_y = vec![messages[1], ScalarField::rand(&mut OsRng)];

    let commitment_x = G1Projective::msm_unchecked(&bases_x, &scalars_x).into_affine();
    let commitment_y = G1Projective::msm_unchecked(&bases_y, &scalars_y).into_affine();

    let (proof_spec, db) = {
        let mut statements = Statements::<Bls12_381>::new();

        let mut meta_statements = MetaStatements::new();
        statements.add(StatementProver::new_statement_from_params(
            params.get(0).unwrap().clone(),
            revealed_messages.clone(),
        ));

        statements.add(PedersenCommitment::new_statement_from_params(
            bases_x.clone(),
            commitment_x,
        ));
        statements.add(PedersenCommitment::new_statement_from_params(
            bases_y.clone(),
            commitment_y,
        ));
        statements.add(StatementProver::new_statement_from_params(
            params.get(0).unwrap().clone(),
            revealed_messages.clone(),
        ));

        let ped_params_x = PairingPedersenParams::<Bls12_381>::new_with_params(
            bases_x[0].into_group(),
            bases_x[1].into_group(),
        );
        let bbs_x = ped_params_x.commit_with_blinding(scalars_x[0], scalars_x[1]);
        let ped_params_y = PairingPedersenParams::<Bls12_381>::new_with_params(
            bases_y[0].into_group(),
            bases_y[1].into_group(),
        );
        let bbs_y = ped_params_y.commit_with_blinding(scalars_y[0], scalars_y[1]);
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, 0), (1, 0)].into_iter().collect::<_>(),
        ));
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, 1), (2, 0)].into_iter().collect::<_>(),
        ));
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, 3), (3, 3)].into_iter().collect::<_>(),
        ));

        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = signing_key.sign(binding_string.as_bytes());
        let signature: Vec<u8> = signature.to_vec();

        let db = device_binding(
            signature,
            public_key,
            binding_string.as_bytes().to_vec(),
            bbs_x,
            ped_params_x,
            bbs_y,
            ped_params_y,
        );

        let proof_spec = ProofSpec::new(statements, meta_statements, vec![], None);
        proof_spec
            .validate()
            .map_err(|err| anyhow::anyhow!("ProofSpec validation error: {err:?}"))?;

        (proof_spec, db)
    };

    let witnesses = {
        let mut witnesses = Witnesses::new();
        witnesses.add(PoKBBSSignatureG1::new_as_witness(
            signatures.get(0).unwrap().clone(),
            unrevealed_messages.clone(),
        ));
        witnesses.add(Witness::PedersenCommitment(scalars_x.clone()));
        witnesses.add(Witness::PedersenCommitment(scalars_y.clone()));
        witnesses.add(PoKBBSSignatureG1::new_as_witness(
            signatures.get(0).unwrap().clone(),
            unrevealed_messages.clone(),
        ));
        witnesses
    };

    let (proof, _) =
        Proof::new::<R, Blake2b512>(rng, proof_spec, witnesses, proof_nonce, Default::default())
            .map_err(|err| anyhow::anyhow!("Failed to create proof: {err:?}"))?;
    Ok((proof, db))
}

#[allow(clippy::too_many_arguments)]
fn verify_proof(
    rng: &mut StdRng,
    proof: Proof<Bls12_381>,
    nonce: ByteArray,
    issuer_pk: ByteArray,
    message_count: u32,
    revealed_messages: BTreeMap<usize, Fr>,
    proof_nonce: Option<String>,
    db: DeviceBinding<p256_arithmetic::ProjectivePoint, 32, tom256::ProjectivePoint, 40, Bls12_381>,
    binding_string: String,
) -> anyhow::Result<bool> {
    if !db.verify(binding_string.into_bytes()) {
        anyhow::bail!("P256 signature invalid");
    }

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
            issuer_pk.clone(),
            revealed_messages.clone(),
        ),
    );
    let bases_x = vec![
        db.eq_x.g2_params.g.into_affine(),
        db.eq_x.g2_params.h.into_affine(),
    ];
    let bases_y = vec![
        db.eq_y.g2_params.g.into_affine(),
        db.eq_y.g2_params.h.into_affine(),
    ];
    let cx = db.eq_x.c2.into_affine();
    let cy = db.eq_y.c2.into_affine();

    // add the statements about the public key commitment
    statements.add(PedersenCommitment::new_statement_from_params(bases_x, cx));
    // add the statements about the public key commitment
    statements.add(PedersenCommitment::new_statement_from_params(bases_y, cy));

    statements.add(
        PoKBBSSignatureG1Verifier::<Bls12_381>::new_statement_from_params(
            SignatureParamsG1::new::<Blake2b512>(&nonce, message_count),
            issuer_pk,
            revealed_messages,
        ),
    );

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, 0), (1, 0)].into_iter().collect::<_>(),
    ));
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, 1), (2, 0)].into_iter().collect::<_>(),
    ));
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, 3), (3, 3)].into_iter().collect::<_>(),
    ));

    let proof_spec = ProofSpec::new(statements, meta_statements, vec![], None);
    proof_spec.validate().unwrap();

    proof
        .verify::<StdRng, Blake2b512>(rng, proof_spec, proof_nonce, Default::default())
        .map_err(|err| anyhow::anyhow!("Failed to verify proof: {err:?}"))?;

    Ok(true)
}

#[test]
pub fn bbs_device_binding_via_p256() -> anyhow::Result<()> {
    let mut rng = StdRng::seed_from_u64(1337);
    // USE-CASE: We have a p256 private key that we use to bind the bbs signature to. For
    // that we use ZK-Attest by cloudflare and equality of DL accross different groups (paper by microsoft).
    // We then use the Bls12381 commitment as a witness and add an equality statement that this is indeed
    // part of our signed signature.
    use proves::group::Coords;
    let signing_key = SigningKey::random(&mut OsRng);
    let pub_key = signing_key.verifying_key().to_sec1_bytes().to_vec();
    let pub_key_p = p256_arithmetic::ProjectivePoint::from_bytes(&pub_key).unwrap();
    let pub_key_p = pub_key_p.to_affine();
    let x = pub_key_p.x().to_be_bytes();
    let y = pub_key_p.y().to_be_bytes();

    // X and Y coordinates in the Bls12381 curve. This is fine as the order is larger than the tom256 (order of base field of p256)
    let x = Fr::from(BigUint::from_bytes_be(&x));
    let y = Fr::from(BigUint::from_bytes_be(&y));

    // Holder has an age
    let age = 21u64;

    // Nonce, is publicy known
    let nonce_bytes = b"nonce";

    let proof_nonce = None;

    // ISSUANCE

    let revealed_indexes = BTreeSet::from([2]);
    let revealed_messages = BTreeMap::from([(2, Fr::from(BigUint::from_bytes_le(b"message 2")))]);

    let (issuer_pk, signature, messages, message_count) = {
        let nonce = BASE64_URL_SAFE_NO_PAD.encode(nonce_bytes);

        let messages = vec![
            x,
            y,
            Fr::from(BigUint::from_bytes_le(b"message 2")),
            Fr::from(age),
            Fr::from(1337u64),
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
    let binding_string = r#"{ "timestamp" : now(), "nonce" : "1234", "whatever"}"#;

    let (proof, zk_attest) = {
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
            messages,
            revealed_indexes,
            proof_nonce.clone(),
            signing_key,
            pub_key,
            binding_string.to_string(),
        )?
    };
    assert!(
        zk_attest.verify(binding_string.as_bytes().to_vec()),
        "zk attest failed"
    );
    let success = verify_proof(
        &mut rng,
        proof,
        nonce_bytes.to_vec(),
        Provider::pk_into_bytes(issuer_pk.clone())?,
        message_count,
        revealed_messages,
        proof_nonce,
        zk_attest,
        binding_string.to_string(),
    )?;

    assert!(success);

    Ok(())
}
