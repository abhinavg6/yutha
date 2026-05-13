//! Build script for `yutha-proto`.
//!
//! Runs `tonic-build` (a superset of `prost-build` that also generates gRPC
//! service stubs) on every `.proto` file under `/spec/` and emits Rust code
//! into `OUT_DIR`. The generated modules are included from `lib.rs`.
//!
//! Configuration choices:
//! - `btree_map(["."])` is enabled for all map fields so encoding is
//!   deterministic (HashMap iteration order is not stable across runs).
//! - The bundled `protoc-bin-vendored` is used so contributors don't need
//!   a system protoc install.
//! - All proto files share `/spec/` as their include path so cross-package
//!   imports (e.g. `import "common.proto"`) resolve.
//! - The control-plane file declares gRPC `service` blocks; tonic-build
//!   emits server + client stubs for those. For the other files (which
//!   don't declare services) tonic-build behaves identically to
//!   prost-build, so they produce the same generated code as before the
//!   tonic switch.
//! - A FileDescriptorSet is emitted alongside the generated code so the
//!   running control plane can expose gRPC reflection without re-running
//!   protoc at runtime.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Locate the bundled protoc and tell prost-build (via tonic-build) to
    // use it.
    let protoc =
        protoc_bin_vendored::protoc_bin_path().expect("bundled protoc should be available");
    std::env::set_var("PROTOC", protoc);

    // /spec/ is two levels up from this crate.
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let spec_root = manifest_dir.join("../../spec");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);

    let proto_files = [
        spec_root.join("common.proto"),
        spec_root.join("passport/passport-v1.proto"),
        spec_root.join("envelope/envelope-v1.proto"),
        spec_root.join("receipt/receipt-v1.proto"),
        spec_root.join("capability/capability-v1.proto"),
        spec_root.join("topology/topology-v1.proto"),
        spec_root.join("control-plane/v1.proto"),
    ];

    // Tell cargo to re-run the build if any of the proto files change.
    for file in &proto_files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    println!("cargo:rerun-if-changed=build.rs");

    // FileDescriptorSet for runtime reflection. The control plane reads
    // this at startup and serves it on the reflection service so tools
    // like `grpcurl localhost:50051 list` work without any extra setup.
    let descriptor_path = out_dir.join("yutha_descriptor.bin");

    tonic_build::configure()
        // Compile servers + clients; the SDKs need clients and the control
        // plane needs servers — generating both unconditionally is
        // cheaper than splitting at the build-script layer.
        .build_server(true)
        .build_client(true)
        // Sorted-key map encoding, same as before. Applies to every map<>
        // field in any of the protos.
        .btree_map(["."])
        .file_descriptor_set_path(&descriptor_path)
        .compile(&proto_files, &[&spec_root])?;

    // Expose the descriptor path as a compile-time env var so lib.rs can
    // `include_bytes!` it without hard-coding OUT_DIR layout.
    println!(
        "cargo:rustc-env=YUTHA_FILE_DESCRIPTOR_SET={}",
        descriptor_path.display()
    );

    Ok(())
}
