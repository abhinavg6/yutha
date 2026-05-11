//! Build script for `yutha-proto`.
//!
//! Runs `prost-build` on every `.proto` file under `/spec/` and emits Rust
//! code into `OUT_DIR`. The generated modules are included from `lib.rs`.
//!
//! Configuration choices:
//! - `btree_map` is enabled for all map fields so encoding is
//!   deterministic (HashMap iteration order is not stable across runs).
//! - The bundled `protoc-bin-vendored` is used so contributors don't need
//!   a system protoc install.
//! - All proto files share `/spec/` as their include path so cross-package
//!   imports (e.g. `import "common.proto"`) resolve.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Locate the bundled protoc and tell prost-build to use it.
    let protoc =
        protoc_bin_vendored::protoc_bin_path().expect("bundled protoc should be available");
    std::env::set_var("PROTOC", protoc);

    // /spec/ is two levels up from this crate.
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let spec_root = manifest_dir.join("../../spec");

    let proto_files = [
        spec_root.join("common.proto"),
        spec_root.join("passport/passport-v1.proto"),
        spec_root.join("envelope/envelope-v1.proto"),
        spec_root.join("receipt/receipt-v1.proto"),
        spec_root.join("capability/capability-v1.proto"),
        spec_root.join("topology/topology-v1.proto"),
    ];

    // Tell cargo to re-run the build if any of the proto files change.
    for file in &proto_files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    println!("cargo:rerun-if-changed=build.rs");

    let mut config = prost_build::Config::new();
    // Deterministic map encoding (sorts keys at serialization time via BTreeMap).
    config.btree_map(["."]);
    // Helpful default: enable `Eq` on generated types where possible. Some
    // floating-point or special fields don't qualify; we let prost decide.
    config.compile_protos(&proto_files, &[&spec_root])?;

    Ok(())
}
