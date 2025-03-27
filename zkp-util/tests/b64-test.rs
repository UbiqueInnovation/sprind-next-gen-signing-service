use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_ff::{BigInt, BigInteger};
use ark_secp256r1::Fq;
use ark_std::UniformRand;
use base64::{prelude::BASE64_STANDARD, Engine};
use equality_across_groups::ec::commitments::from_base_field_to_scalar_field;
use num_bigint::BigUint;
use rand_core::OsRng;
use zkp_util::{
    device_binding::{BlsFr, SecpFr},
    SECP_GEN,
};

fn to_bytes_le(nums: Vec<u64>) -> Vec<u8> {
    nums.into_iter().flat_map(|num| num.to_le_bytes()).collect()
}

fn from_bytes_le(bytes: Vec<u8>) -> Vec<u64> {
    assert!(bytes.len() % 8 == 0, "Byte length must be a multiple of 8");

    bytes
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
        .collect()
}

#[test]
pub fn bytes_test() {
    let nums = vec![1u64, 3u64, 3u64, 7u64];

    let nums_rt = from_bytes_le(to_bytes_le(nums.clone()));

    assert_eq!(nums, nums_rt);

    let bi = BigInt::<4>::new(nums.try_into().unwrap());
    let bi_rt = BigInt::<4>::new(
        from_bytes_le(to_bytes_le(bi.0.to_vec()))
            .try_into()
            .unwrap(),
    );
    assert_eq!(bi, bi_rt);
}

#[test]
pub fn b64_test() {
    let mut rng = OsRng;

    let secret_key = SecpFr::rand(&mut rng);
    let public_key = (SECP_GEN * secret_key).into_affine();

    let x = BlsFr::from(BigUint::from_bytes_be(
        &public_key.x().unwrap().0.to_bytes_be(),
    ));

    let bi: BigInt<4> = x.into_bigint();

    let bytes = to_bytes_le(bi.0.to_vec());
    let bi = BigInt::<4>::new(from_bytes_le(bytes).try_into().unwrap());

    let x2 = BlsFr::from_bigint(bi).unwrap();

    assert_eq!(x, x2);
}
