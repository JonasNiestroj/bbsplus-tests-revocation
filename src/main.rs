use accumulator::{
    generate_fr, Accumulator, Coefficient, Element, MembershipWitness, PublicKey, SecretKey,
};
use bls12_381_plus::{G1Projective, G2Projective, Scalar};
use rand_core::SeedableRng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize, Serializer};
use std::collections::{HashMap, HashSet};
use std::vec::Vec;
use uint_zigzag::Uint;
extern crate group;
use group::GroupEncoding;
use rand_core::RngCore;

use criterion::{criterion_group, criterion_main, Criterion};

use allosaur::{AccParams, Credential, PublicKeys, Server};
use base64::{engine::general_purpose, Engine as _};
use lazy_static::lazy_static;
use once_cell::sync::Lazy;
use rocket::http::{ContentType, RawStr, Status};
use rocket::tokio::sync::OnceCell;
use rocket::{get, launch, post, routes};
use serde_big_array::BigArray;
use std::sync::Mutex;

use crate::allosaur::Witness;

pub mod accumulator;
pub mod allosaur;

static PARAMS: Lazy<OnceCell<AccParams>> = Lazy::new(|| OnceCell::new());

lazy_static! {
    static ref CREDENTIALS: Mutex<HashMap<u8, Credential>> = Mutex::new(HashMap::new());
    static ref SERVER: Mutex<Option<Server>> = Mutex::new(None);
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofChallenge {
    non_revocation_proof: String,
    non_revocation_challenge: String,
}

/*fn main() {
    let params = AccParams::default();
    let mut server = Server::gen(&params);
    let mut users = Vec::new();
    for _ in 0..10 {
        users.push(User::new(&server, UserID::random()));
        server.add(users.last().unwrap().get_id());
        users.last_mut().unwrap().wit(&params, &server);
    }

    users.push(User::new(&server, UserID::random()));

    for i in 0..11 {
        let mut ephemeral_challenge = [0u8; 2 * 128];
        rand_core::OsRng.fill_bytes(&mut ephemeral_challenge);
        let proof = users[i].make_membership_proof(
            &params,
            &server.get_public_keys(),
            &ephemeral_challenge,
        );

        println!(
            "{}",
            Witness::check_membership_proof(
                &proof,
                &params,
                &server.get_public_keys(),
                &server.get_accumulator(),
                &ephemeral_challenge
            )
        );
    }
}*/

#[post("/revoke?<credential_index>")]
fn revoke_credential(credential_index: &str) -> Status {
    let mut server_option = SERVER.lock().unwrap();
    let mut server = server_option.as_mut().unwrap();
    let credentials = CREDENTIALS.lock().unwrap();
    let credential = credentials
        .get(&credential_index.parse::<u8>().unwrap())
        .unwrap();

    server.delete(credential.get_index());

    return Status::Ok;
}

#[post("/add")]
fn add_credential() -> String {
    let mut server_option = SERVER.lock().unwrap();
    let mut server = server_option.as_mut().unwrap();

    let mut map = CREDENTIALS.lock().unwrap();

    let credential_index: u8 = map.len().try_into().unwrap();
    let element_index = Element::hash(vec![credential_index].as_slice());
    let mut credential = Credential::new(&server, element_index);

    server.add(credential.get_index());
    credential.wit(PARAMS.get().unwrap(), &server);

    map.insert(credential_index, credential);

    return credential_index.to_string();
}

#[post("/verify?<credential_index>")]
fn verify_credential(credential_index: &str) -> String {
    let credentials = CREDENTIALS.lock().unwrap();
    let credential = credentials
        .get(&credential_index.parse::<u8>().unwrap())
        .unwrap();

    let mut server_option = SERVER.lock().unwrap();

    let server = server_option.as_mut().unwrap();

    let mut ephemeral_challenge = [0u8; 2 * 128];
    rand_core::OsRng.fill_bytes(&mut ephemeral_challenge);
    let proof = credential.make_membership_proof(
        &PARAMS.get().unwrap(),
        &server.get_public_keys(),
        &ephemeral_challenge,
    );

    let base64 = general_purpose::STANDARD.encode(&proof);
    let challenge_base64 = general_purpose::STANDARD.encode(&ephemeral_challenge);

    return serde_json::to_string(&ProofChallenge {
        non_revocation_challenge: challenge_base64,
        non_revocation_proof: base64,
    })
    .unwrap();
}

#[post("/check", data = "<proof>")]
fn check(proof: &str) -> Status {
    println!("proof: {}", proof);
    let proof_challenge = serde_json::from_str::<ProofChallenge>(proof).unwrap();
    let proof = general_purpose::STANDARD
        .decode(proof_challenge.non_revocation_proof)
        .unwrap();
    let challenge = general_purpose::STANDARD
        .decode(proof_challenge.non_revocation_challenge)
        .unwrap();

    let proof_array: [u8; 432] = proof.try_into().unwrap();
    let challenge_array: [u8; 2 * 128] = challenge.try_into().unwrap();

    let params = PARAMS.get().unwrap();
    let server_option = SERVER.lock().unwrap();
    let server = server_option.as_ref().unwrap();

    let checked = Witness::check_membership_proof(
        &proof_array,
        &params,
        &server.get_public_keys(),
        &server.get_accumulator(),
        &challenge_array,
    );

    if checked {
        return Status::Ok;
    }

    return Status::BadRequest;
}

#[launch]
async fn rocket() -> _ {
    let params = AccParams::default();
    let mut server = Server::gen(&params);

    *SERVER.lock().unwrap() = Some(server);

    PARAMS.set(params);

    rocket::build().mount(
        "/",
        routes![revoke_credential, verify_credential, check, add_credential],
    )
}

// Various helper data structures to serialize update messages into byte strings

#[derive(Debug)]
struct UserUpdateMessage {
    epoch: usize,
    shares: Vec<Scalar>,
}

impl Serialize for UserUpdateMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = Vec::with_capacity(64);
        output.append(&mut Uint::from(self.epoch).to_vec());
        output.append(&mut Uint::from(self.shares.len()).to_vec());
        for s in &self.shares {
            output.extend_from_slice(&s.to_be_bytes());
        }
        serializer.serialize_bytes(&output)
    }
}

#[derive(Debug)]
struct ServerUpdateMessage {
    d_poly: Vec<Scalar>,
    v_poly: Vec<G1Projective>,
}

impl Serialize for ServerUpdateMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = Vec::with_capacity(64);
        output.append(&mut Uint::from(self.d_poly.len()).to_vec());
        for s in &self.d_poly {
            output.extend_from_slice(&s.to_be_bytes());
        }
        output.append(&mut Uint::from(self.v_poly.len()).to_vec());
        for s in &self.v_poly {
            output.extend_from_slice(&s.to_bytes().as_ref());
        }
        serializer.serialize_bytes(&output)
    }
}

#[derive(Debug)]
struct VBUpdateMessage {
    additions: Vec<Element>,
    deletions: Vec<Element>,
    deltas: Vec<Coefficient>,
}

impl Serialize for VBUpdateMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = Vec::with_capacity(64);
        output.append(&mut Uint::from(self.additions.len()).to_vec());
        for s in &self.additions {
            output.extend_from_slice(&s.0.to_be_bytes());
        }
        output.append(&mut Uint::from(self.deletions.len()).to_vec());
        for s in &self.deletions {
            output.extend_from_slice(&s.0.to_be_bytes());
        }
        output.append(&mut Uint::from(self.deltas.len()).to_vec());
        for s in &self.deltas {
            output.extend_from_slice(&s.0.to_bytes().as_ref())
        }
        serializer.serialize_bytes(&output)
    }
}
