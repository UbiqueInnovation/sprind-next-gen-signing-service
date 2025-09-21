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

use rocket::{get, serde::json::Json};

use next_gen_signatures::generate_crypto_routes;
use next_gen_signatures::{Engine, BASE64_URL_SAFE_NO_PAD};
use rocket_errors::anyhow;

use crate::models::common::KeyPair;

generate_crypto_routes!(Fips204MlDsa44Provider);
generate_crypto_routes!(Fips204MlDsa65Provider);
generate_crypto_routes!(Fips204MlDsa87Provider);
