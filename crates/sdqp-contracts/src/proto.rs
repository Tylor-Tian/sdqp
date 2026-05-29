pub const PROTO_PACKAGES: &[(&str, &str)] = &[
    ("common.proto", "sdqp.common.v1"),
    ("auth.proto", "sdqp.auth.v1"),
    ("query.proto", "sdqp.query.v1"),
    ("audit.proto", "sdqp.audit.v1"),
    ("project.proto", "sdqp.project.v1"),
    ("approval.proto", "sdqp.approval.v1"),
    ("permission.proto", "sdqp.permission.v1"),
    ("evidence.proto", "sdqp.evidence.v1"),
    ("watermark.proto", "sdqp.watermark.v1"),
    ("ueba.proto", "sdqp.ueba.v1"),
];

pub mod common {
    tonic::include_proto!("sdqp.common.v1");
}

pub mod auth {
    tonic::include_proto!("sdqp.auth.v1");
}

pub mod query {
    tonic::include_proto!("sdqp.query.v1");
}

pub mod audit {
    tonic::include_proto!("sdqp.audit.v1");
}

pub mod project {
    tonic::include_proto!("sdqp.project.v1");
}

pub mod approval {
    tonic::include_proto!("sdqp.approval.v1");
}

pub mod permission {
    tonic::include_proto!("sdqp.permission.v1");
}

pub mod evidence {
    tonic::include_proto!("sdqp.evidence.v1");
}

pub mod watermark {
    tonic::include_proto!("sdqp.watermark.v1");
}

pub mod ueba {
    tonic::include_proto!("sdqp.ueba.v1");
}
