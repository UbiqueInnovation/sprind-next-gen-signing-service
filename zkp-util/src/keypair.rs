use rand_core::RngCore;
use rdf_proofs::KeyPairBase58Btc;

pub fn generate_keypair<R: RngCore>(rng: &mut R) -> (String, String) {
    let kp = KeyPairBase58Btc::new(rng).unwrap();
    (kp.public_key, kp.secret_key)
}
