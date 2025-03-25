use ark_bls12_381::{Bls12_381, G1Affine as BlsG1Affine};
use ark_secp256r1::{Affine as SecpAffine, G_GENERATOR_X, G_GENERATOR_Y};
use bbs_plus::prelude::{KeypairG1, SignatureG1};
use dock_crypto_utils::commitment::PedersenCommitmentKey;
use equality_across_groups::{
    eq_across_groups::ProofLargeWitness as ProofLargeWitnessOrig, tom256::Affine as Tom256Affine,
};

pub mod circuits;
pub mod device_binding;
pub mod vc;

pub const SECP_GEN: SecpAffine = SecpAffine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);

const WITNESS_BIT_SIZE: usize = 64;
const CHALLENGE_BIT_SIZE: usize = 180;
const ABORT_PARAM: usize = 8;
const RESPONSE_BYTE_SIZE: usize = 32;
const NUM_REPS: usize = 1;
const NUM_CHUNKS: usize = 4;

pub type PedersenCommitmentKeySecp = PedersenCommitmentKey<SecpAffine>;
pub type PedersenCommitmentKeyTom = PedersenCommitmentKey<Tom256Affine>;
pub type PedersenCommitmentKeyBls = PedersenCommitmentKey<BlsG1Affine>;

pub type ProofLargeWitness = ProofLargeWitnessOrig<
    Tom256Affine,
    BlsG1Affine,
    NUM_CHUNKS,
    WITNESS_BIT_SIZE,
    CHALLENGE_BIT_SIZE,
    ABORT_PARAM,
    RESPONSE_BYTE_SIZE,
    NUM_REPS,
>;

pub type BBSKeypair = KeypairG1<Bls12_381>;
pub type BBSSignature = SignatureG1<Bls12_381>;

#[cfg(test)]
mod tests {
    use super::*;

    use ark_bls12_381::Fr as BlsFr;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_secp256r1::{Affine as SecpAffine, Fq, Fr as SecpFr};
    use ark_std::UniformRand;
    use blake2::Blake2b512;
    use bulletproofs_plus_plus::prelude::SetupParams as BppSetupParams;
    use dock_crypto_utils::{
        randomized_mult_checker::RandomizedMultChecker,
        transcript::{new_merlin_transcript, Transcript},
    };
    use equality_across_groups::{
        ec::commitments::{from_base_field_to_scalar_field, PointCommitmentWithOpening},
        pok_ecdsa_pubkey::{PoKEcdsaSigCommittedPublicKeyProtocol, TransformedEcdsaSig},
        tom256::Affine as Tom256Affine,
    };
    use kvac::bbs_sharp::ecdsa;
    use rand_core::OsRng;

    const _KEY_GRAPH: &str = r#"
    <did:example:issuer0> <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
    <did:example:issuer0#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
    <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer0> .
    <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "z4893E1L7AeYfqaduUdLYgcxefWAah8gJB8RhPi7JHQkdRbe" .
    <did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "zUC77BjGcGDVWfBdgzqwzp3uuWkoWuRMe8pnx4dkncia5t9LKHVt96BPGBizeSU7BKiV35h1tsuVwHUVt4arZuckxGCb2tTsB3fsY66mQNs5Bwoac2w2iyYFe8uenBUYdAiveEr" .
    "#;

    const _VC: &str = r#"
    <did:example:john> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
    <did:example:john> <http://schema.org/name> "John Smith" .
    <http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
    <http://example.org/vcred/00> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:john> .
    <http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
    <http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    <http://example.org/vcred/00> <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    "#;

    const _VC_PROOF: &str = r#"
    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
    _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
    _:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
    "#;

    #[test]
    fn pok_ecdsa_pubkey_committed_in_bls12_381_commitment() {
        // This test creates an ECDSA public key, commits to its coordinates in Pedersen commitments on the Tom-256 curve
        // as well as the BLS12-381 curve.
        // It then creates an ECDSA signature, proves that it can be verified by the public key committed
        // on the Tom-256 curve.
        // It then proves that the key (its coordinates) committed in the Tom-256 curve are the same as the ones
        // committed in the BLS12-381 curve.

        let mut rng = OsRng::default();

        let comm_key_secp = PedersenCommitmentKeySecp::new::<Blake2b512>(b"test1");
        let comm_key_tom = PedersenCommitmentKeyTom::new::<Blake2b512>(b"test2");
        let comm_key_bls = PedersenCommitmentKeyBls::new::<Blake2b512>(b"test3");

        // Bulletproofs++ setup
        let base = 2;
        let mut bpp_setup_params = BppSetupParams::<Tom256Affine>::new_for_perfect_range_proof::<
            Blake2b512,
        >(
            b"test", base, WITNESS_BIT_SIZE as u16, NUM_CHUNKS as u32
        );
        bpp_setup_params.G = comm_key_tom.g;
        bpp_setup_params.H_vec[0] = comm_key_tom.h;

        // ECDSA public key setup
        let sk = SecpFr::rand(&mut rng);
        let pk = (SECP_GEN * sk).into_affine();

        // Commit to ECDSA public key on Tom-256 curve
        let comm_pk = PointCommitmentWithOpening::new(&mut rng, &pk, &comm_key_tom).unwrap();

        // NOTE: This what should be written in to the issued credential (device binding x/y)
        // Commit to ECDSA public key on BLS12-381 curve
        let pk_x = from_base_field_to_scalar_field::<Fq, BlsFr>(pk.x().unwrap());
        let pk_y = from_base_field_to_scalar_field::<Fq, BlsFr>(pk.y().unwrap());

        let bls_comm_pk_rx = BlsFr::rand(&mut rng);
        let bls_comm_pk_ry = BlsFr::rand(&mut rng);
        let bls_comm_pk_x = comm_key_bls.commit(&pk_x, &bls_comm_pk_rx);
        let bls_comm_pk_y = comm_key_bls.commit(&pk_y, &bls_comm_pk_ry);

        let message = SecpFr::rand(&mut rng);
        let sig = ecdsa::Signature::new_prehashed(&mut rng, message, sk);

        let transformed_sig = TransformedEcdsaSig::new(&sig, message, pk).unwrap();
        transformed_sig.verify_prehashed(message, pk).unwrap();

        let mut prover_transcript = new_merlin_transcript(b"test");
        prover_transcript.append(b"comm_key_secp", &comm_key_secp);
        prover_transcript.append(b"comm_key_tom", &comm_key_tom);
        prover_transcript.append(b"comm_key_bls", &comm_key_bls);
        prover_transcript.append(b"bpp_setup_params", &bpp_setup_params);
        prover_transcript.append(b"comm_pk", &comm_pk.comm);
        prover_transcript.append(b"bls_comm_pk_x", &bls_comm_pk_x);
        prover_transcript.append(b"bls_comm_pk_y", &bls_comm_pk_y);
        prover_transcript.append(b"message", &message);

        let protocol = PoKEcdsaSigCommittedPublicKeyProtocol::<128>::init(
            &mut rng,
            transformed_sig,
            message,
            pk,
            comm_pk.clone(),
            &comm_key_secp,
            &comm_key_tom,
        )
        .unwrap();
        protocol
            .challenge_contribution(&mut prover_transcript)
            .unwrap();
        let challenge_prover = prover_transcript.challenge_scalar(b"challenge");
        let proof = protocol.gen_proof(&challenge_prover);

        // Proof that x coordinate is same in both Tom-256 and BLS12-381 commitments
        let proof_eq_pk_x = ProofLargeWitness::new(
            &mut rng,
            &comm_pk.x,
            comm_pk.r_x,
            bls_comm_pk_rx,
            &comm_key_tom,
            &comm_key_bls,
            base,
            bpp_setup_params.clone(),
            &mut prover_transcript,
        )
        .unwrap();

        // Proof that y coordinate is same in both Tom-256 and BLS12-381 commitments
        let proof_eq_pk_y = ProofLargeWitness::new(
            &mut rng,
            &comm_pk.y,
            comm_pk.r_y,
            bls_comm_pk_ry,
            &comm_key_tom,
            &comm_key_bls,
            base,
            bpp_setup_params.clone(),
            &mut prover_transcript,
        )
        .unwrap();

        let mut verifier_transcript = new_merlin_transcript(b"test");
        verifier_transcript.append(b"comm_key_secp", &comm_key_secp);
        verifier_transcript.append(b"comm_key_tom", &comm_key_tom);
        verifier_transcript.append(b"comm_key_bls", &comm_key_bls);
        verifier_transcript.append(b"bpp_setup_params", &bpp_setup_params);
        verifier_transcript.append(b"comm_pk", &comm_pk.comm);
        verifier_transcript.append(b"bls_comm_pk_x", &bls_comm_pk_x);
        verifier_transcript.append(b"bls_comm_pk_y", &bls_comm_pk_y);
        verifier_transcript.append(b"message", &message);
        proof
            .challenge_contribution(&mut verifier_transcript)
            .unwrap();

        let challenge_verifier = verifier_transcript.challenge_scalar(b"challenge");
        assert_eq!(challenge_prover, challenge_verifier);

        let mut checker_1 = RandomizedMultChecker::<SecpAffine>::new_using_rng(&mut rng);
        let mut checker_2 = RandomizedMultChecker::<Tom256Affine>::new_using_rng(&mut rng);

        proof
            .verify_using_randomized_mult_checker(
                message,
                comm_pk.comm,
                &challenge_verifier,
                comm_key_secp,
                comm_key_tom,
                &mut checker_1,
                &mut checker_2,
            )
            .unwrap();

        proof_eq_pk_x
            .verify(
                &comm_pk.comm.x,
                &bls_comm_pk_x,
                &comm_key_tom,
                &comm_key_bls,
                &bpp_setup_params,
                &mut verifier_transcript,
            )
            .unwrap();

        proof_eq_pk_y
            .verify(
                &comm_pk.comm.y,
                &bls_comm_pk_y,
                &comm_key_tom,
                &comm_key_bls,
                &bpp_setup_params,
                &mut verifier_transcript,
            )
            .unwrap();
    }
}

#[cfg(test)]
mod tests2 {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::UniformRand;
    use bbs_plus::prelude::{KeypairG1, SignatureG1, SignatureParamsG1, SignatureParamsG2};
    use rand_core::OsRng;

    #[test]
    fn test_bbs() {
        let mut rng = OsRng;

        let params_g1 = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, 4);
        let params_g2 = SignatureParamsG2::<Bls12_381>::generate_using_rng(&mut rng, 4);
        let keypair = KeypairG1::generate_using_rng(&mut rng, &params_g2);

        let messages = [
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
        ];

        let _signature =
            SignatureG1::new(&mut rng, &messages, &keypair.secret_key, &params_g1).unwrap();
    }
}
