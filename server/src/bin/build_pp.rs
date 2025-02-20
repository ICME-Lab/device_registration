use halo2curves::bn256::Bn256;
use nova::{
    nebula::rs::PublicParams, onchain::decider::Decider, provider::{Bn256EngineKZG, GrumpkinEngine}, traits::{snark::RelaxedR1CSSNARKTrait, Engine}
};
use radius_circuit::circuit::ProximityCircuit;
use rand::thread_rng;

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova::provider::hyperkzg::EvaluationEngine<Bn256, E1>;
type EE2 = nova::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova::spartan::ppsnark::RelaxedR1CSSNARK<E1, EE1>; 
type S2 = nova::spartan::ppsnark::RelaxedR1CSSNARK<E2, EE2>; 


fn main() {
    // produce public parameters, used to produce vk, the verifier key (Only neefs to be done only once for a given circuit)
    println!("Producing public parameters...");
    let circuit_primary = ProximityCircuit::<<E1 as Engine>::Scalar>::default();
    let rs_pp = PublicParams::<E1>::setup(&circuit_primary.clone(), &*S1::ck_floor(), &*S2::ck_floor());

    let mut rng = thread_rng();
    // Needs the VerifierKey type to implement Deserialize to be able to retrieve it rather than the pp.
    let (_decider_pk, _decider_vk) = Decider::setup(&rs_pp, &mut rng, 1).unwrap();
    let serialized_pp = serde_json::to_string(&rs_pp).unwrap();
    if !std::path::Path::new("storage").exists() {
        std::fs::create_dir("storage").unwrap();
    }
    std::fs::write("storage/pp.json", serialized_pp).unwrap();
}
