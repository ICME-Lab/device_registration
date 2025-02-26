use nova::{
    provider::{self, PallasEngine, VestaEngine},
    spartan,
    traits::{circuit::TrivialCircuit, snark::RelaxedR1CSSNARKTrait, Engine},
    CompressedSNARK, PublicParams,
};
use radius_circuit::circuit::ProximityCircuit;

type E1 = PallasEngine;
type E2 = VestaEngine;

type EE1<G1> = provider::ipa_pc::EvaluationEngine<G1>;
type EE2<G2> = provider::ipa_pc::EvaluationEngine<G2>;

type S1Prime<G1> = spartan::ppsnark::RelaxedR1CSSNARK<G1, EE1<G1>>;
type S2Prime<G2> = spartan::ppsnark::RelaxedR1CSSNARK<G2, EE2<G2>>;

fn main() {
    // produce public parameters, used to produce vk, the verifier key (Only neefs to be done only once for a given circuit)
    println!("Producing public parameters...");
    let circuit_primary = ProximityCircuit::<<E1 as Engine>::Scalar>::default();
    let circuit_secondary = TrivialCircuit::<<E2 as Engine>::Scalar>::default();
    let pp = PublicParams::<PallasEngine>::setup(
        &circuit_primary.clone(),
        &circuit_secondary.clone(),
        &*S1Prime::ck_floor(),
        &*S2Prime::ck_floor(),
    )
    .unwrap();

    // Needs the VerifierKey type to implement Deserialize to be able to retrieve it rather than the pp.
    let (_pk, _vk) = CompressedSNARK::<E1, S1Prime<E1>, S2Prime<E2>>::setup(&pp).unwrap();

    let serialized_pp = serde_json::to_string(&pp).unwrap();
    if !std::path::Path::new("storage").exists() {
        std::fs::create_dir("storage").unwrap();
    }
    std::fs::write("storage/pp.json", serialized_pp).unwrap();
}
