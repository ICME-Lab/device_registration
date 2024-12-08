use nova_snark::traits::{circuit::TrivialTestCircuit, Group};
use nova_snark::{provider, spartan};
use nova_snark::{CompressedSNARK, PublicParams};
use radius_circuit::circuit::ProximityCircuit;

type G1 = pasta_curves::pallas::Point;
type G2 = pasta_curves::vesta::Point;

type EE1<G1> = provider::ipa_pc::EvaluationEngine<G1>;
type EE2<G2> = provider::ipa_pc::EvaluationEngine<G2>;

type S1Prime<G1> = spartan::ppsnark::RelaxedR1CSSNARK<G1, EE1<G1>>;
type S2Prime<G2> = spartan::ppsnark::RelaxedR1CSSNARK<G2, EE2<G2>>;

fn main() {
    // produce public parameters, used to produce vk, the verifier key (could only be done only once for a given circuit)
    println!("Producing public parameters...");
    let circuit_primary = ProximityCircuit::<<G1 as Group>::Scalar>::default();
    let circuit_secondary = TrivialTestCircuit::<<G2 as Group>::Scalar>::default();
    let pp = PublicParams::<
        G1,
        G2,
        ProximityCircuit<<G1 as Group>::Scalar>,
        TrivialTestCircuit<<G2 as Group>::Scalar>,
    >::setup(circuit_primary.clone(), circuit_secondary.clone());

    let (_pk, vk) = CompressedSNARK::<_, _, _, _, S1Prime<G1>, S2Prime<G2>>::setup(&pp).unwrap();

    let serialized_vk = serde_json::to_string(&vk).unwrap();
    if !std::path::Path::new("storage").exists() {
        std::fs::create_dir("storage").unwrap();
    }
    std::fs::write("storage/vk.json", serialized_vk).unwrap();
}
