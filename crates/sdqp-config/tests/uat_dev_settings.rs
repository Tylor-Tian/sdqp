use std::{collections::HashMap, path::PathBuf};

use sdqp_config::{AppSettings, Environment};

#[test]
fn phase0_dev_settings_can_be_loaded_with_test_override() {
    let env = HashMap::from([
        ("SDQP_ENVIRONMENT".to_string(), "ci".to_string()),
        ("SDQP_WORKER_PORT".to_string(), "28081".to_string()),
    ]);

    let settings = AppSettings::from_env_map(&env).expect("settings");
    assert_eq!(settings.environment, Environment::Ci);
    assert_eq!(settings.worker.port, 28081);
}

#[test]
fn uat_profile_loader_supports_local_docker_and_prod_sim_profiles() {
    let config_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("configs");

    let docker = AppSettings::from_profile_files(&config_root, Environment::LocalDocker, None)
        .expect("local docker settings");
    assert_eq!(docker.environment, Environment::LocalDocker);
    assert_eq!(docker.api.host, "0.0.0.0");
    assert_eq!(docker.frontend.api_base_url, "");

    let prod_sim = AppSettings::from_profile_files(&config_root, Environment::ProdSim, None)
        .expect("prod sim settings");
    assert_eq!(prod_sim.environment, Environment::ProdSim);
    assert_eq!(prod_sim.api.port, 38080);
    assert_eq!(prod_sim.worker.port, 38081);
}
