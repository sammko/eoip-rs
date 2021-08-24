mod lib;

use std::net::Ipv4Addr;
use anyhow::Result;
use lib::{Eoip, TunnelConfig};

fn main() -> Result<()> {
    Eoip::new(TunnelConfig::new(
        Some(Ipv4Addr::new(10, 60, 1, 2)),
        Ipv4Addr::new(10, 60, 1, 1),
        999,
        "",
        Some(3),
        Some(5),
    ))
    .run();
}
