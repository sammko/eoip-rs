eoip-rs is a Rust implementation of the Mikrotik EoIP protocol for Linux, with
full support for keepalive transmission and remote peer timeouts.

    eoip-rs
    
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
