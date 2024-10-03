use std::fmt::Display;

use anyhow::Result;
use rocket::form::{self, DataField, FromForm, ValueField};

pub type ByteArray = Vec<u8>;

pub trait CryptoProvider {
    type GenParams: for<'a> FromForm<'a> + TestDefault;
    type SignParams: for<'a> FromForm<'a> + TestDefault;
    type VerifyParams: for<'a> FromForm<'a> + TestDefault;

    type PublicKey;
    type SecretKey;

    fn gen_keypair(params: Self::GenParams) -> Result<(Self::PublicKey, Self::SecretKey)>;

    fn pk_into_bytes(pk: Self::PublicKey) -> Result<ByteArray>;
    fn pk_from_bytes(bytes: ByteArray) -> Result<Self::PublicKey>;

    fn sk_into_bytes(sk: Self::SecretKey) -> Result<ByteArray>;
    fn sk_from_bytes(bytes: ByteArray) -> Result<Self::SecretKey>;

    fn sign(sk: &Self::SecretKey, params: Self::SignParams) -> Result<ByteArray>;
    fn verify(pk: Self::PublicKey, sig: ByteArray, params: Self::VerifyParams) -> Result<bool>;
}

#[derive(Debug)]
pub struct NoArguments;

impl Display for NoArguments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:#?}", self))
    }
}

#[rocket::async_trait]
impl<'r> FromForm<'r> for NoArguments {
    type Context = ();

    fn init(_: form::Options) -> Self::Context {}

    fn push_value(_: &mut Self::Context, _: ValueField<'r>) {}

    async fn push_data(_: &mut Self::Context, _: DataField<'r, '_>) {}

    fn finalize(_: Self::Context) -> form::Result<'r, Self> {
        Ok(NoArguments)
    }
}

pub trait TestDefault {
    fn default_for_test() -> Self;
}

impl TestDefault for NoArguments {
    fn default_for_test() -> Self {
        NoArguments
    }
}
