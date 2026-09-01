fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 仓内 vendored 拷贝；权威来源仍是 santaizi-agent/proto/santaizi.proto，
    // CI 会 diff 检查漂移。单独 clone 本仓即可 cargo build。
    let proto_dir = std::path::PathBuf::from("proto");
    let proto_file = proto_dir.join("santaizi.proto");
    println!("cargo:rerun-if-changed={}", proto_file.display());
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[proto_file], std::slice::from_ref(&proto_dir))?;
    Ok(())
}
