use std::convert::TryInto;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::time::Instant;

use anyhow::Result;
use nix::sys::select::{select, FdSet};
use nix::sys::time::{TimeSpec, TimeValLike};
use nix::sys::timerfd::{ClockId, Expiration, TimerFd, TimerFlags, TimerSetTimeFlags};
use socket2::{Domain, SockAddr, Socket, Type};
use tun_tap::{Iface, Mode};

struct TunnelConfig<'a> {
    local: Option<Ipv4Addr>,
    remote: Ipv4Addr,
    tunnel_id: u16,
    tap_name: &'a str,
    keepalive_interval: Option<u64>,
    recv_timeout: Option<u64>,
}

impl<'a> TunnelConfig<'a> {
    fn new(
        local: Option<Ipv4Addr>,
        remote: Ipv4Addr,
        tunnel_id: u16,
        tap_name: &'a str,
        keepalive_interval: Option<u64>,
        recv_timeout: Option<u64>,
    ) -> Self {
        TunnelConfig {
            local,
            remote,
            tunnel_id,
            tap_name,
            keepalive_interval,
            recv_timeout,
        }
    }
}

struct Eoip<'a> {
    config: TunnelConfig<'a>,
    last_received: Option<Instant>,
}

impl<'a> Eoip<'a> {
    fn new(config: TunnelConfig<'a>) -> Self {
        Eoip {
            config,
            last_received: None,
        }
    }

    pub fn run(&mut self) -> ! {
        match self._run() {
            Ok(_) => {}
            Err(e) => eprintln!("{}", e),
        }
        panic!("Exited");
    }

    fn _run(&mut self) -> Result<()> {
        let mut tap = Iface::without_packet_info(self.config.tap_name, Mode::Tap)?;
        eprintln!("Running on {}", tap.name());

        let mut socket = Socket::new(Domain::IPV4, Type::RAW, Some(47.into()))?;

        if let Some(local) = self.config.local {
            socket.bind(&SockAddr::from(SocketAddrV4::new(local, 0)))?;
        }
        socket.connect(&SockAddr::from(SocketAddrV4::new(self.config.remote, 0)))?;

        let timer = if let Some(t) = self.config.keepalive_interval {
            let tfd = TimerFd::new(ClockId::CLOCK_MONOTONIC, TimerFlags::empty())?;
            tfd.set(
                Expiration::Interval(TimeSpec::seconds(t as i64)),
                TimerSetTimeFlags::empty(),
            )?;
            self.send_keepalive(&mut socket)?;
            Some(tfd)
        } else {
            None
        };

        let mut read_fds = FdSet::new();
        loop {
            read_fds.insert(tap.as_raw_fd());
            read_fds.insert(socket.as_raw_fd());
            if let Some(ref tfd) = timer {
                read_fds.insert(tfd.as_raw_fd());
            }
            let _ = select(None, &mut read_fds, None, None, None)?;

            if read_fds.contains(tap.as_raw_fd()) {
                let mut buf = vec![0u8; 65536];
                match tap.recv(&mut buf[8..]) {
                    Ok(n) => {
                        self.received_tap(n, &mut buf[..n + 8], &mut socket);
                    }
                    Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => panic!("tap.recv: {}", e),
                };
            }
            if read_fds.contains(socket.as_raw_fd()) {
                let mut buf = vec![0u8; 65536];
                match socket.read(buf.as_mut_slice()) {
                    Ok(n) => {
                        self.received_raw(&buf[..n], &mut tap);
                    }
                    Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => panic!("socket.read: {}", e),
                };
            }
            if let Some(ref tfd) = timer {
                if read_fds.contains(tfd.as_raw_fd()) {
                    tfd.wait()?;
                    self.send_keepalive(&mut socket)?;
                }
            }
        }
    }

    fn send_keepalive(&self, socket: &mut Socket) -> Result<()> {
        let mut buf = [32, 1, 100, 0, 0, 0, 0, 0];
        buf[6..8].copy_from_slice(&(self.config.tunnel_id as u16).to_le_bytes());
        socket.write(&buf)?;
        Ok(())
    }

    fn received_raw(&mut self, packet: &[u8], tap: &mut Iface) {
        if packet.len() < 28 {
            eprintln!("Too short packet received!");
            return;
        }
        let _ip_hdr = &packet[0..19];
        let gre_hdr = &packet[20..24];
        if &gre_hdr[2..] != &[0x64, 0x00] {
            // type not mikrotik eoip
            return;
        }
        if &gre_hdr[..2] != &[0x20, 0x01] {
            eprintln!("Unexpected GRE flags: {:?}", &gre_hdr[..2]);
            return;
        }
        let tunnel_id = u16::from_le_bytes(packet[26..28].try_into().unwrap());
        if tunnel_id != self.config.tunnel_id {
            return;
        }
        let data_len_header = u16::from_be_bytes(packet[24..26].try_into().unwrap()) as usize;
        let data_len = packet.len() - 20 - 8;
        if data_len_header != data_len {
            eprintln!("Data length mismatch!");
            return;
        }
        self.last_received = Some(Instant::now());
        if data_len == 0 {
            return;
        }
        let data = &packet[28..];
        match tap.send(data) {
            Ok(_) => {}
            Err(ref e) if matches!(e.raw_os_error(), Some(5)) => {}
            Err(e) => {
                eprintln!("Failed to send to TAP interface: {}", e);
            }
        }
    }

    fn received_tap(&self, length: usize, buf: &mut [u8], socket: &mut Socket) {
        if let Some(timeout) = self.config.recv_timeout {
            match self.last_received {
                None => return,
                Some(t) if t.elapsed().as_secs() >= timeout => return,
                _ => {}
            }
        }
        buf[..4].copy_from_slice(&[32, 1, 100, 0]);
        buf[4..6].copy_from_slice(&(length as u16).to_be_bytes());
        buf[6..8].copy_from_slice(&(self.config.tunnel_id as u16).to_le_bytes());
        match socket.write(&buf) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Failed to write to raw socket: {}", e);
            }
        }
    }
}

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
