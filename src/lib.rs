pub mod config;
pub mod identity;
pub mod monitor;
pub mod netip;
pub mod report;
pub mod v2;

pub mod pb {
    #![allow(clippy::large_enum_variant)]
    tonic::include_proto!("proto");
}
