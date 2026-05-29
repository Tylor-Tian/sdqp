use std::path::PathBuf;

fn main() {
    let proto_root = PathBuf::from("../../proto");
    let protos = [
        proto_root.join("common.proto"),
        proto_root.join("auth.proto"),
        proto_root.join("query.proto"),
        proto_root.join("audit.proto"),
        proto_root.join("project.proto"),
        proto_root.join("approval.proto"),
        proto_root.join("permission.proto"),
        proto_root.join("evidence.proto"),
        proto_root.join("watermark.proto"),
        proto_root.join("ueba.proto"),
    ];

    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&protos, &[proto_root])
        .expect("compile protobuf contracts");
}
