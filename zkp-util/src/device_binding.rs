use anyhow::{anyhow, Context};
use ark_bls12_381::G1Affine as BlsG1Affine;
use ark_ec::AffineRepr;
use ark_secp256r1::Fq;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use blake2::Blake2b512;
use bulletproofs_plus_plus::prelude::SetupParams as BppSetupParams;
use dock_crypto_utils::commitment::PedersenCommitmentKey;
use dock_crypto_utils::{
    randomized_mult_checker::RandomizedMultChecker,
    transcript::{new_merlin_transcript, Transcript},
};
use equality_across_groups::{
    ec::commitments::{
        from_base_field_to_scalar_field, PointCommitment, PointCommitmentWithOpening,
    },
    pok_ecdsa_pubkey::{
        PoKEcdsaSigCommittedPublicKey, PoKEcdsaSigCommittedPublicKeyProtocol, TransformedEcdsaSig,
    },
};
use equality_across_groups::{
    eq_across_groups::ProofLargeWitness as ProofLargeWitnessOrig, tom256::Affine as Tom256Affine,
};
use kvac::bbs_sharp::ecdsa;
use rand_core::RngCore;

const WITNESS_BIT_SIZE: usize = 64;
const CHALLENGE_BIT_SIZE: usize = 180;
const ABORT_PARAM: usize = 8;
const RESPONSE_BYTE_SIZE: usize = 32;
const NUM_REPS: usize = 1;
const NUM_CHUNKS: usize = 4;

pub const DEVICE_BINDING_KEY: &str = "https://zkp-ld.org/deviceBinding";
pub const DEVICE_BINDING_KEY_X: &str = "https://zkp-ld.org/deviceBinding#x";
pub const DEVICE_BINDING_KEY_Y: &str = "https://zkp-ld.org/deviceBinding#y";

pub type SecpFr = ark_secp256r1::Fr;
pub type SecpFq = ark_secp256r1::Fq;
pub type SecpAffine = ark_secp256r1::Affine;
pub type BlsFr = ark_bls12_381::Fr;

type PedersenCommitmentKeySecp = PedersenCommitmentKey<SecpAffine>;
type PedersenCommitmentKeyTom = PedersenCommitmentKey<Tom256Affine>;
type PedersenCommitmentKeyBls = PedersenCommitmentKey<BlsG1Affine>;
type ProofLargeWitness = ProofLargeWitnessOrig<
    Tom256Affine,
    BlsG1Affine,
    NUM_CHUNKS,
    WITNESS_BIT_SIZE,
    CHALLENGE_BIT_SIZE,
    ABORT_PARAM,
    RESPONSE_BYTE_SIZE,
    NUM_REPS,
>;

#[derive(Debug, Clone)]
pub struct DeviceBinding {
    pub proof: PoKEcdsaSigCommittedPublicKey,
    pub eq_x: ProofLargeWitness,
    pub eq_y: ProofLargeWitness,

    pub comm_pk: PointCommitment<Tom256Affine>,

    pub bls_comm_key: Vec<BlsG1Affine>,
    pub bls_comm_pk_x: BlsG1Affine,
    pub bls_comm_pk_y: BlsG1Affine,

    pub bls_scalars_x: Vec<BlsFr>,
    pub bls_scalars_y: Vec<BlsFr>,
}

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct DeviceBindingPresentation {
    pub proof: PoKEcdsaSigCommittedPublicKey,
    pub eq_x: ProofLargeWitness,
    pub eq_y: ProofLargeWitness,

    pub comm_pk: PointCommitment<Tom256Affine>,

    pub bls_comm_key: Vec<BlsG1Affine>,
    pub bls_comm_pk_x: BlsG1Affine,
    pub bls_comm_pk_y: BlsG1Affine,
}

impl DeviceBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new<R: RngCore>(
        rng: &mut R,
        public_key: SecpAffine,
        message: SecpFr,
        message_signature: ecdsa::Signature,
        comm_key_secp_label: &[u8],
        comm_key_tom_label: &[u8],
        comm_key_bls_label: &[u8],
        bpp_setup_label: &[u8],
        merlin_transcript_label: &'static [u8],
        challenge_label: &'static [u8],
    ) -> anyhow::Result<Self> {
        let comm_key_secp = PedersenCommitmentKeySecp::new::<Blake2b512>(comm_key_secp_label);
        let comm_key_tom = PedersenCommitmentKeyTom::new::<Blake2b512>(comm_key_tom_label);
        let comm_key_bls = PedersenCommitmentKeyBls::new::<Blake2b512>(comm_key_bls_label);

        let bls_comm_key = vec![comm_key_bls.g, comm_key_bls.h];

        let base = 2;
        let mut bpp_setup_params =
            BppSetupParams::<Tom256Affine>::new_for_perfect_range_proof::<Blake2b512>(
                bpp_setup_label,
                base,
                WITNESS_BIT_SIZE as u16,
                NUM_CHUNKS as u32,
            );
        bpp_setup_params.G = comm_key_tom.g;
        bpp_setup_params.H_vec[0] = comm_key_tom.h;

        // Commit to ECDSA public key on Tom-256 curve
        let comm_pk = PointCommitmentWithOpening::new(rng, &public_key, &comm_key_tom)
            .map_err(|e| anyhow!("Failed to create PointCommitmentWithOpening: {e:?}"))?;

        // Commit to ECDSA public key on BLS12-381 curve
        let pk_x = from_base_field_to_scalar_field::<Fq, BlsFr>(
            public_key
                .x()
                .context("Failed to get public_key x coordinate!")?,
        );
        let pk_y = from_base_field_to_scalar_field::<Fq, BlsFr>(
            public_key
                .y()
                .context("Failed to get public_key y coordinate!")?,
        );

        let bls_comm_pk_rx = BlsFr::rand(rng);
        let bls_comm_pk_ry = BlsFr::rand(rng);
        let bls_comm_pk_x = comm_key_bls.commit(&pk_x, &bls_comm_pk_rx);
        let bls_comm_pk_y = comm_key_bls.commit(&pk_y, &bls_comm_pk_ry);
        let bls_scalars_x = vec![pk_x, bls_comm_pk_rx];
        let bls_scalars_y = vec![pk_y, bls_comm_pk_ry];

        let transformed_sig =
            TransformedEcdsaSig::new(&message_signature, message, public_key).unwrap();
        transformed_sig
            .verify_prehashed(message, public_key)
            .unwrap();

        let mut prover_transcript = new_merlin_transcript(merlin_transcript_label);
        prover_transcript.append(b"comm_key_secp", &comm_key_secp);
        prover_transcript.append(b"comm_key_tom", &comm_key_tom);
        prover_transcript.append(b"comm_key_bls", &comm_key_bls);
        prover_transcript.append(b"bpp_setup_params", &bpp_setup_params);
        prover_transcript.append(b"comm_pk", &comm_pk.comm);
        prover_transcript.append(b"bls_comm_pk_x", &bls_comm_pk_x);
        prover_transcript.append(b"bls_comm_pk_y", &bls_comm_pk_y);
        prover_transcript.append(b"message", &message);

        let protocol = PoKEcdsaSigCommittedPublicKeyProtocol::<128>::init(
            rng,
            transformed_sig,
            message,
            public_key,
            comm_pk.clone(),
            &comm_key_secp,
            &comm_key_tom,
        )
        .map_err(|e| anyhow!("Failed to create the protocol: {e:?}"))?;
        protocol
            .challenge_contribution(&mut prover_transcript)
            .map_err(|e| anyhow!("Failed to challenge contribution of the protocol: {e:?}"))?;
        let challenge_prover = prover_transcript.challenge_scalar(challenge_label);
        let proof = protocol.gen_proof(&challenge_prover);

        // Proof that x coordinate is same in both Tom-256 and BLS12-381 commitments
        let proof_eq_pk_x = ProofLargeWitness::new(
            rng,
            &comm_pk.x,
            comm_pk.r_x,
            bls_comm_pk_rx,
            &comm_key_tom,
            &comm_key_bls,
            base,
            bpp_setup_params.clone(),
            &mut prover_transcript,
        )
        .map_err(|e| anyhow!("Failed to create proof_eq_pk_x: {e:?}"))?;

        // Proof that y coordinate is same in both Tom-256 and BLS12-381 commitments
        let proof_eq_pk_y = ProofLargeWitness::new(
            rng,
            &comm_pk.y,
            comm_pk.r_y,
            bls_comm_pk_ry,
            &comm_key_tom,
            &comm_key_bls,
            base,
            bpp_setup_params.clone(),
            &mut prover_transcript,
        )
        .map_err(|e| anyhow!("Failed to create proof_eq_pk_x: {e:?}"))?;

        Ok(Self {
            proof,
            eq_x: proof_eq_pk_x,
            eq_y: proof_eq_pk_y,
            comm_pk: comm_pk.comm,
            bls_comm_key,
            bls_comm_pk_x,
            bls_comm_pk_y,
            bls_scalars_x,
            bls_scalars_y,
        })
    }

    pub fn present(self) -> DeviceBindingPresentation {
        DeviceBindingPresentation {
            proof: self.proof,
            eq_x: self.eq_x,
            eq_y: self.eq_y,
            comm_pk: self.comm_pk,
            bls_comm_key: self.bls_comm_key,
            bls_comm_pk_x: self.bls_comm_pk_x,
            bls_comm_pk_y: self.bls_comm_pk_y,
        }
    }
}

impl DeviceBindingPresentation {
    #[allow(clippy::too_many_arguments)]
    pub fn verify<R: RngCore>(
        &self,
        rng: &mut R,
        message: SecpFr,
        comm_key_secp_label: &[u8],
        comm_key_tom_label: &[u8],
        comm_key_bls_label: &[u8],
        bpp_setup_label: &[u8],
        merlin_transcript_label: &'static [u8],
        challenge_label: &'static [u8],
    ) -> anyhow::Result<()> {
        let comm_key_secp = PedersenCommitmentKeySecp::new::<Blake2b512>(comm_key_secp_label);
        let comm_key_tom = PedersenCommitmentKeyTom::new::<Blake2b512>(comm_key_tom_label);
        let comm_key_bls = PedersenCommitmentKeyBls::new::<Blake2b512>(comm_key_bls_label);

        let base = 2;
        let mut bpp_setup_params =
            BppSetupParams::<Tom256Affine>::new_for_perfect_range_proof::<Blake2b512>(
                bpp_setup_label,
                base,
                WITNESS_BIT_SIZE as u16,
                NUM_CHUNKS as u32,
            );
        bpp_setup_params.G = comm_key_tom.g;
        bpp_setup_params.H_vec[0] = comm_key_tom.h;

        let mut verifier_transcript = new_merlin_transcript(merlin_transcript_label);
        verifier_transcript.append(b"comm_key_secp", &comm_key_secp);
        verifier_transcript.append(b"comm_key_tom", &comm_key_tom);
        verifier_transcript.append(b"comm_key_bls", &comm_key_bls);
        verifier_transcript.append(b"bpp_setup_params", &bpp_setup_params);
        verifier_transcript.append(b"comm_pk", &self.comm_pk);
        verifier_transcript.append(b"bls_comm_pk_x", &self.bls_comm_pk_x);
        verifier_transcript.append(b"bls_comm_pk_y", &self.bls_comm_pk_y);
        verifier_transcript.append(b"message", &message);
        self.proof
            .challenge_contribution(&mut verifier_transcript)
            .map_err(|e| anyhow!("Failed to challenge contribution: {e:?}"))?;

        let challenge_verifier = verifier_transcript.challenge_scalar(challenge_label);

        self.proof
            .verify_using_randomized_mult_checker(
                message,
                self.comm_pk,
                &challenge_verifier,
                comm_key_secp,
                comm_key_tom,
                &mut RandomizedMultChecker::<SecpAffine>::new_using_rng(rng),
                &mut RandomizedMultChecker::<Tom256Affine>::new_using_rng(rng),
            )
            .map_err(|e| anyhow!("Failed to verify proof: {e:?}"))?;

        self.eq_x
            .verify(
                &self.comm_pk.x,
                &self.bls_comm_pk_x,
                &comm_key_tom,
                &comm_key_bls,
                &bpp_setup_params,
                &mut verifier_transcript,
            )
            .map_err(|e| anyhow!("Failed to verify eq_x: {e:?}"))?;

        self.eq_y
            .verify(
                &self.comm_pk.y,
                &self.bls_comm_pk_y,
                &comm_key_tom,
                &comm_key_bls,
                &bpp_setup_params,
                &mut verifier_transcript,
            )
            .map_err(|e| anyhow!("Failed to verify eq_y: {e:?}"))?;

        Ok(())
    }
}

pub fn change_field(p: &SecpFq) -> BlsFr {
    from_base_field_to_scalar_field::<Fq, BlsFr>(p)
}

#[test]
pub fn test_device_binding() {
    use std::io::Cursor;

    use ark_ec::CurveGroup;
    use ark_secp256r1::{G_GENERATOR_X, G_GENERATOR_Y};

    const SECP_GEN: SecpAffine = SecpAffine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);

    let mut rng = rand_core::OsRng;

    let secret_key = SecpFr::rand(&mut rng);
    let public_key = (SECP_GEN * secret_key).into_affine();

    let message = SecpFr::rand(&mut rng);
    let message_signature = ecdsa::Signature::new_prehashed(&mut rng, message, secret_key);

    let db = DeviceBinding::new(
        &mut rng,
        public_key,
        message,
        message_signature,
        b"comm-key-secp",
        b"comm-key-tom",
        b"comm-key-bls",
        b"bpp-setup",
        b"transcript",
        b"challenge",
    )
    .unwrap();

    let presentation = db.present();

    let mut bytes = Vec::<u8>::new();
    presentation.serialize_compressed(&mut bytes).unwrap();

    println!("{}", bytes.len());

    let presentation =
        DeviceBindingPresentation::deserialize_compressed(Cursor::new(bytes)).unwrap();

    presentation
        .verify(
            &mut rng,
            message,
            b"comm-key-secp",
            b"comm-key-tom",
            b"comm-key-bls",
            b"bpp-setup",
            b"transcript",
            b"challenge",
        )
        .unwrap();
}
