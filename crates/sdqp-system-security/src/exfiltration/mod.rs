mod dns_tunnel;
mod http_covert;

pub use dns_tunnel::{DnsTunnelFinding, inspect_dns_tunnel};
pub use http_covert::{HttpCovertFinding, inspect_http_covert_channel};
