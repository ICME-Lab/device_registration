use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs;

#[derive(Serialize)]
struct RegisterDeviceBody {
    diddoc: String,
}

#[derive(Deserialize)]
struct RegisterResult {
    message: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let client = reqwest::Client::new();

    let diddoc = fs::read_to_string("./device_register/peerDIDDoc.json").expect("file read");
    println!("DIDDoc: {}", diddoc);

    let body = RegisterDeviceBody { diddoc };
    let url = "http://127.0.0.1:3000/register_device";
    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&body).expect("JSON serialization"))
        .send()
        .await?;

    let result: RegisterResult = response.json().await?;
    println!("Result: {}", result.message);
    Ok(())
}
