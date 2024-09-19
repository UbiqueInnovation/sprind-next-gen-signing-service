use anyhow::Result;

pub type ByteArray = Vec<u8>;

pub trait CryptoProvider {
    type PublicKey;
    type SecretKey;

    fn gen_keypair() -> Result<(Self::PublicKey, Self::SecretKey)>;

    fn pk_into_bytes(pk: Self::PublicKey) -> Result<ByteArray>;
    fn pk_from_bytes(bytes: ByteArray) -> Result<Self::PublicKey>;

    fn sk_into_bytes(sk: Self::SecretKey) -> Result<ByteArray>;
    fn sk_from_bytes(bytes: ByteArray) -> Result<Self::SecretKey>;

    fn sign(sk: &Self::SecretKey, msg: ByteArray) -> Result<ByteArray>;
    fn verify(pk: &Self::PublicKey, msg: ByteArray, sig: ByteArray) -> Result<bool>;
}
