pub const API_SERVICE_NAME: &str = "sdqp-api";
pub const WORKER_SERVICE_NAME: &str = "sdqp-worker";
pub const PHASE0_MILESTONE: &str = "phase0";

pub fn phase0_services() -> Vec<&'static str> {
    vec![API_SERVICE_NAME, WORKER_SERVICE_NAME]
}

#[cfg(test)]
mod tests {
    use super::{API_SERVICE_NAME, WORKER_SERVICE_NAME, phase0_services};

    #[test]
    fn phase0_services_contains_api_and_worker() {
        let services = phase0_services();
        assert_eq!(services, vec![API_SERVICE_NAME, WORKER_SERVICE_NAME]);
    }
}
