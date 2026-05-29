use sdqp_config::AppSettings;
use sdqp_worker::run;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = AppSettings::from_process_env().unwrap_or_else(|_| AppSettings::local_dev());
    tracing_subscriber::fmt()
        .with_env_filter(settings.observability.log_filter.clone())
        .init();
    run(settings).await?;
    Ok(())
}
