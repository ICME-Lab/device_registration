use zk_engine::nova::{
    provider::{ipa_pc, PallasEngine, VestaEngine},
    spartan::{ppsnark, snark},
    traits::{circuit::TrivialCircuit, snark::RelaxedR1CSSNARKTrait, Engine},
    PublicParams,
};
use zk_engine::precompiles::signing::SigningCircuit;

type E1 = PallasEngine;
type E2 = VestaEngine;
type EE1 = ipa_pc::EvaluationEngine<E1>;
type EE2 = ipa_pc::EvaluationEngine<E2>;
type S1 = ppsnark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = snark::RelaxedR1CSSNARK<E2, EE2>;

fn main() {
    // produce public parameters, used to produce vk, the verifier key (could only be done only once for a given circuit)
    println!("Producing public parameters...");
    type C1 = SigningCircuit<<E1 as Engine>::Scalar>;
    type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;
    let circuit_primary = C1::new([1; 32].to_vec(), [1; 32].to_vec());
    let circuit_secondary = C2::default();
    let pp = PublicParams::<E1>::setup(
        &circuit_primary,
        &circuit_secondary,
        &*S1::ck_floor(),
        &*S2::ck_floor(),
    )
    .unwrap();

    let serialized_pp = serde_json::to_string(&pp).unwrap();
    if !std::path::Path::new("storage").exists() {
        std::fs::create_dir("storage").unwrap();
    }
    std::fs::write("storage/public_params.json", serialized_pp).unwrap();
}
