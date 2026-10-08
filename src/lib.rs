pub mod config;
pub mod dialcache;
pub mod dns;
pub mod identity;
pub mod monitor;
pub mod nat;
pub mod netip;
pub mod pki;
pub mod probe;
pub mod report;
pub mod v2;
pub mod wal;

pub mod pb {
    #![allow(clippy::large_enum_variant)]
    tonic::include_proto!("proto");
}
