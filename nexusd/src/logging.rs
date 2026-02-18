use tracing_subscriber::{EnvFilter, fmt};

pub fn init() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt()
        .without_time()
        .with_env_filter(filter)
        .init();
}
