use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let verify = env::args().any(|arg| arg == "--verify");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");

    let openapi_path = root.join("openapi").join("sdqp-v1.json");
    let generated_path = root.join("generated").join("proto-contract-index.json");

    let openapi = serde_json::to_string_pretty(&sdqp_contracts::build_openapi_document())?;
    let proto_index = serde_json::to_string_pretty(&sdqp_contracts::build_proto_contract_index())?;

    if verify {
        let current_openapi = fs::read_to_string(&openapi_path)?;
        let current_index = fs::read_to_string(&generated_path)?;
        if current_openapi != openapi {
            return Err(format!(
                "OpenAPI artifact drift detected: {}",
                openapi_path.display()
            )
            .into());
        }
        if current_index != proto_index {
            return Err(format!(
                "Proto contract index drift detected: {}",
                generated_path.display()
            )
            .into());
        }
        return Ok(());
    }

    fs::write(openapi_path, openapi)?;
    fs::write(generated_path, proto_index)?;
    Ok(())
}
