```rust
#[test]
fn pok_ecdsa_pubkey_committed_in_bls12_381_commitment() {
    // This test creates an ECDSA public key, commits to its coordinates in Pedersen commitments on the Tom-256 curve
    // as well as the BLS12-381 curve.
    // It then creates an ECDSA signature, proves that it can be verified by the public key committed
    // on the Tom-256 curve.
    // It then proves that the key (its coordinates) committed in the Tom-256 curve are the same as the ones
    // committed in the BLS12-381 curve.

    let mut rng = OsRng::default();

    const WITNESS_BIT_SIZE: usize = 64;
    const CHALLENGE_BIT_SIZE: usize = 180;
    const ABORT_PARAM: usize = 8;
    const RESPONSE_BYTE_SIZE: usize = 32;
    const NUM_REPS: usize = 1;
    const NUM_CHUNKS: usize = 4;

    let comm_key_secp = PedersenCommitmentKey::<Affine>::new::<Blake2b512>(b"test1");
    let comm_key_tom = PedersenCommitmentKey::<Tom256Affine>::new::<Blake2b512>(b"test2");
    let comm_key_bls = PedersenCommitmentKey::<BlsG1Affine>::new::<Blake2b512>(b"test3");

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
    let sk = Fr::rand(&mut rng);
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

    let mut prov_time = vec![];
    let mut ver_time = vec![];
    let num_iters = 10;
    for i in 0..num_iters {
        let message = Fr::rand(&mut rng);
        let sig = ecdsa::Signature::new_prehashed(&mut rng, message, sk);

        let start = Instant::now();
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
        let proof_eq_pk_x = ProofLargeWitness::<
            Tom256Affine,
            BlsG1Affine,
            NUM_CHUNKS,
            WITNESS_BIT_SIZE,
            CHALLENGE_BIT_SIZE,
            ABORT_PARAM,
            RESPONSE_BYTE_SIZE,
            NUM_REPS,
        >::new(
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
        let proof_eq_pk_y = ProofLargeWitness::<
            Tom256Affine,
            BlsG1Affine,
            NUM_CHUNKS,
            WITNESS_BIT_SIZE,
            CHALLENGE_BIT_SIZE,
            ABORT_PARAM,
            RESPONSE_BYTE_SIZE,
            NUM_REPS,
        >::new(
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
        prov_time.push(start.elapsed());

        let start = Instant::now();
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

        // verify_using_randomized_mult_checker can be used like previous test to make it much faster.
        proof
            .verify(
                message,
                &comm_pk.comm,
                &challenge_verifier,
                &comm_key_secp,
                &comm_key_tom,
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
        ver_time.push(start.elapsed());

        if i == 0 {
            println!(
                "Total proof size = {} bytes",
                proof.compressed_size()
                    + proof_eq_pk_x.compressed_size()
                    + proof_eq_pk_y.compressed_size()
            );
            println!(
                "Proof size for equality of committed x and y coordinates = {} bytes",
                proof_eq_pk_x.compressed_size() + proof_eq_pk_y.compressed_size()
            );
        }
    }

    println!("For {} iterations", num_iters);
    println!("Proving time: {:?}", statistics(prov_time));
    println!("Verifying time: {:?}", statistics(ver_time));
}
```