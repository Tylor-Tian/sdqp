use sdqp_api::watermark_grpc::{parse_grpc_addr, run_standalone_watermark_grpc};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr =
        std::env::var("SDQP_WATERMARK_GRPC_ADDR").unwrap_or_else(|_| "127.0.0.1:50051".into());
    let addr = parse_grpc_addr(&addr)?;
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();
    run_standalone_watermark_grpc(addr).await?;
    Ok(())
}
