use std::time::Instant;

use halo2curves::bn256::Bn256;
use nova::{nebula::rs::{PublicParams, RecursiveSNARK}, onchain::decider::{Decider, DeciderVerifierKey}, provider::{Bn256EngineKZG, GrumpkinEngine}, traits::{snark::RelaxedR1CSSNARKTrait, Engine}};
use radius_circuit::circuit::ProximityCircuit;
use ff::Field;
use rand::rngs::ThreadRng;
use sha2::Digest;

use crate::utils::{load_from_bson, save_to_bson, sign, Signature};

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova::provider::hyperkzg::EvaluationEngine<Bn256, E1>;
type EE2 = nova::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova::spartan::snark::RelaxedR1CSSNARK<E1, EE1>; // non-preprocessing SNARK
type S2 = nova::spartan::snark::RelaxedR1CSSNARK<E2, EE2>; // non-preprocessing SNARK

pub fn generate_rs_proof(
    circuit: ProximityCircuit<<E1 as Engine>::Scalar>,
) -> (RecursiveSNARK<E1>, PublicParams<E1>) {
    println!("Producing public parameters...");
    // produce public parameters
    let start = Instant::now();
    let rs_pp = PublicParams::<E1>::setup(&circuit.clone(), &*S1::ck_floor(), &*S2::ck_floor());
    println!("Public parameters setup took: {:?}", start.elapsed());

    let num_steps = 3;
    let z0 = [<E1 as Engine>::Scalar::ZERO];

    // produce a recursive SNARK
    let mut rs = RecursiveSNARK::<E1>::new(&rs_pp, &circuit, &z0).unwrap();
    let mut ic_i = <E1 as Engine>::Scalar::ZERO;
    for i in 0..num_steps {
        // TODO: Random longitude and latitude between 4900 and 5100
        let circuit = ProximityCircuit::new(
            <<E1 as Engine>::Scalar>::from(4900 + i),
            <<E1 as Engine>::Scalar>::from(5000 + i),
        );
        rs.prove_step(&rs_pp, &circuit, ic_i).unwrap();

        ic_i = rs.increment_commitment(&rs_pp, &circuit);
    }

    // verify the recursive SNARK
    let res = rs.verify(&rs_pp, num_steps as usize, &z0, ic_i);
    assert!(res.is_ok());
    println!("RecursiveSNARK::verify: {:?}", res.is_ok(),);

    let zn = res.unwrap();
    // sanity: check the claimed output with a direct computation of the same
    assert_eq!(zn, vec![<E1 as Engine>::Scalar::ONE]);

    (rs, rs_pp)
}

/// Produce the prover and verifier keys for compressed snark
pub fn setup_decider(rs_pp: PublicParams<E1>, rng: &mut ThreadRng) -> DeciderVerifierKey {
    // let start = Instant::now();
    // let (_, decider_vk) = Decider::setup(&rs_pp, rng, 1).unwrap();
    // println!("Decider setup took: {:?}", start.elapsed());
    // save_to_bson(&decider_vk, "decider_vk.bson");

    let decider_vk = load_from_bson::<DeciderVerifierKey>("decider_vk.bson");
    // println!("decider_vk: {:?}", decider_vk);
    decider_vk
}

pub fn generate_decider_proof(
    rs: RecursiveSNARK<E1>,
    rs_pp: PublicParams<E1>,
    rng: &mut ThreadRng,
) -> Decider {
    // produce a compressed SNARK
    // let start = Instant::now();
    // let res = Decider::prove(&rs_pp, &decider_pk, &rs, &mut rng);
    // assert!(res.is_ok());
    // let compressed_snark = res.unwrap();
    // println!("Decider prove took: {:?}", start.elapsed());
    // save_to_bson(&compressed_snark, "compressed_snark.bson");
    let compressed_snark = load_from_bson::<Decider>("compressed_snark.bson");
    compressed_snark
}

pub fn sign_proof_with_device(compressed_snark: &Decider) -> ([u8; 32], Signature) {
    // compute proof hash
    let proof_serialized = serde_json::to_string(compressed_snark).expect("JSON serialization");
    let hash = sha2::Sha256::digest(proof_serialized.as_bytes());
    let hash: [u8; 32] = hash.into();

    // send proof_serialized to device ( DEVICE_URL ), receive signature
    println!("Sending hash to device to be signed...");
    let hex_hash = "0x".to_owned() + &hex::encode(hash);
    let signature = sign(hex_hash);
    println!("Signature: \nv: {}, \nr: {}, \ns: {}", signature.v, signature.r, signature.s);

    (hash, signature)
}

pub fn verify_proof(compressed_snark: &Decider, decider_vk: &DeciderVerifierKey) -> bool {
    let start = Instant::now();
    let res = compressed_snark.verify(decider_vk.clone());
    println!("Verification took: {:?}", start.elapsed());
    res.is_ok()
}