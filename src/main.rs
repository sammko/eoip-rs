mod lib;

use anyhow::{anyhow, Result};
use lib::{Eoip, TunnelConfig};

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const HELP_MESSAGE: &str = r#"eoip-rs

USAGE:
    eoip-rs [OPTIONS]

OPTIONS:
    -l, --local       IP address of local tunnel endpoint
    -r, --remote      IP address of remote tunnel endpoint
    -t, --tunid       Tunnel ID
    -I, --interface   Name of the created tap interface
    -k, --keepalive   Interval of keepalive packet transmissions [seconds]
    -W, --timeout     How often the peer needs to send data to be
                      considered alive [seconds]
    -h, --help        Shows this message
    -v, --version     Shows version information
"#;

fn parse_args() -> Result<TunnelConfig> {
    use lexopt::prelude::*;
    let mut local = None;
    let mut remote = None;
    let mut tunnel_id = None;
    let mut tap_name = None;
    let mut keepalive_interval = None;
    let mut recv_timeout = None;
    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('l') | Long("local") => local = Some(parser.value()?.parse()?),
            Short('r') | Long("remote") => remote = Some(parser.value()?.parse()?),
            Short('t') | Long("tunid") => tunnel_id = Some(parser.value()?.parse()?),
            Short('I') | Long("interface") => tap_name = Some(parser.value()?.parse()?),
            Short('k') | Long("keepalive") => keepalive_interval = Some(parser.value()?.parse()?),
            Short('W') | Long("timeout") => recv_timeout = Some(parser.value()?.parse()?),
            Short('h') | Long("help") => {
                print!("{}", HELP_MESSAGE);
                std::process::exit(0);
            }
            Short('v') | Long("version") => {
                println!("eoip-rs {}", VERSION);
                std::process::exit(0);
            }
            _ => return Err(arg.unexpected().into()),
        }
    }
    Ok(TunnelConfig::new(
        local,
        remote.ok_or(anyhow!("Remote address is required"))?,
        tunnel_id.ok_or(anyhow!("Tunnel ID is required"))?,
        tap_name,
        keepalive_interval,
        recv_timeout,
    ))
}

fn main() -> Result<()> {
    Eoip::new(parse_args()?)?.run();
}
