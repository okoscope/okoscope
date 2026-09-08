fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let mut prost = prost_build::Config::new();
    prost.protoc_executable(protoc);
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_with_config(prost, &["proto/okoscope/v1/agent.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/okoscope/v1/agent.proto");
    Ok(())
}
