use zk_engine::precompiles::signing::SigningCircuit;

fn main() {
    // produce public parameters, used to produce vk, the verifier key (could only be done only once for a given circuit)
    println!("Producing public parameters...");
    let circuit_primary = SigningCircuit::default();
    let pp = circuit_primary.get_public_params().unwrap();

    let serialized_pp = serde_json::to_string(&pp).unwrap();
    if !std::path::Path::new("storage").exists() {
        std::fs::create_dir("storage").unwrap();
    }
    std::fs::write("storage/public_params.json", serialized_pp).unwrap();
}
