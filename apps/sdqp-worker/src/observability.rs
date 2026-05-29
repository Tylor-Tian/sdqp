use std::sync::atomic::{AtomicU64, Ordering};

use http::StatusCode;

#[derive(Debug, Default)]
pub struct HttpMetrics {
    requests_total: AtomicU64,
    responses_2xx_total: AtomicU64,
    responses_4xx_total: AtomicU64,
    responses_5xx_total: AtomicU64,
}

impl HttpMetrics {
    pub fn record(&self, status: StatusCode) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        match status.as_u16() {
            200..=299 => {
                self.responses_2xx_total.fetch_add(1, Ordering::Relaxed);
            }
            400..=499 => {
                self.responses_4xx_total.fetch_add(1, Ordering::Relaxed);
            }
            500..=599 => {
                self.responses_5xx_total.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn render_prometheus(&self, service_name: &str) -> String {
        format!(
            concat!(
                "# HELP sdqp_http_requests_total Total HTTP requests observed by the service.\n",
                "# TYPE sdqp_http_requests_total counter\n",
                "sdqp_http_requests_total{{service=\"{service}\"}} {requests}\n",
                "# HELP sdqp_http_responses_2xx_total Total 2xx responses observed by the service.\n",
                "# TYPE sdqp_http_responses_2xx_total counter\n",
                "sdqp_http_responses_2xx_total{{service=\"{service}\"}} {responses_2xx}\n",
                "# HELP sdqp_http_responses_4xx_total Total 4xx responses observed by the service.\n",
                "# TYPE sdqp_http_responses_4xx_total counter\n",
                "sdqp_http_responses_4xx_total{{service=\"{service}\"}} {responses_4xx}\n",
                "# HELP sdqp_http_responses_5xx_total Total 5xx responses observed by the service.\n",
                "# TYPE sdqp_http_responses_5xx_total counter\n",
                "sdqp_http_responses_5xx_total{{service=\"{service}\"}} {responses_5xx}\n"
            ),
            service = service_name,
            requests = self.requests_total.load(Ordering::Relaxed),
            responses_2xx = self.responses_2xx_total.load(Ordering::Relaxed),
            responses_4xx = self.responses_4xx_total.load(Ordering::Relaxed),
            responses_5xx = self.responses_5xx_total.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::HttpMetrics;

    #[test]
    fn prometheus_output_tracks_status_families() {
        let metrics = HttpMetrics::default();
        metrics.record(http::StatusCode::OK);
        metrics.record(http::StatusCode::BAD_REQUEST);
        metrics.record(http::StatusCode::INTERNAL_SERVER_ERROR);

        let output = metrics.render_prometheus("sdqp-worker");
        assert!(output.contains("sdqp_http_requests_total{service=\"sdqp-worker\"} 3"));
        assert!(output.contains("sdqp_http_responses_2xx_total{service=\"sdqp-worker\"} 1"));
        assert!(output.contains("sdqp_http_responses_4xx_total{service=\"sdqp-worker\"} 1"));
        assert!(output.contains("sdqp_http_responses_5xx_total{service=\"sdqp-worker\"} 1"));
    }
}
