/* Copyright 2025 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

use std::collections::BTreeMap;

use next_gen_signatures::{common::CryptoProvider, generate_crypto_routes};
use next_gen_signatures::{Engine, BASE64_URL_SAFE_NO_PAD};
use rocket::{get, serde::json::Json};
use rocket_errors::anyhow;

use crate::models::common::KeyPair;

generate_crypto_routes!(BbsPlusG1Provider);
generate_crypto_routes!(BbsPlusG2Provider);

#[get("/pok/create?<signature>&<messages>&<nonce>&<revealed_indexes>")]
#[allow(non_snake_case)]
pub fn BbsPlusG1Provider_create_pok_of_sig(
    signature: String,
    messages: Vec<String>,
    nonce: String,
    revealed_indexes: Vec<usize>,
) -> Json<String> {
    use next_gen_signatures::{crypto::BbsPlusG1Provider as Provider, BASE64_URL_SAFE_NO_PAD};

    let signature = BASE64_URL_SAFE_NO_PAD.decode(signature).unwrap();
    let revealed_indexes = revealed_indexes.into_iter().collect();
    let proof = Provider::create_pok_of_sig(signature, messages, nonce, revealed_indexes).unwrap();

    Json(BASE64_URL_SAFE_NO_PAD.encode(proof))
}

#[get("/pok/verify?<proof>&<revealed_messages>&<public_key>&<nonce>&<message_count>")]
#[allow(non_snake_case)]
pub fn BbsPlusG1Provider_verify_pok_of_sig(
    proof: String,
    revealed_messages: BTreeMap<usize, String>,
    public_key: String,
    nonce: String,
    message_count: u32,
) -> Json<bool> {
    use next_gen_signatures::{crypto::BbsPlusG1Provider as Provider, BASE64_URL_SAFE_NO_PAD};

    let proof = BASE64_URL_SAFE_NO_PAD.decode(proof).unwrap();

    let public_key = BASE64_URL_SAFE_NO_PAD.decode(public_key).unwrap();
    let public_key = Provider::pk_from_bytes(public_key).unwrap();

    let revealed_messages = revealed_messages.into_iter().collect();

    let success =
        Provider::verify_pok_of_sig(proof, revealed_messages, public_key, nonce, message_count)
            .unwrap();

    Json(success)
}
