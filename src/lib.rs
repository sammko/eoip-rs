use std::convert::TryInto;
use std::io::{ErrorKind, Read};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::process::exit;

use anyhow::{anyhow, Context, Result};
use nix::ioctl_write_ptr;
use nix::sys::select::{select, FdSet};
use nix::sys::time::{TimeSpec, TimeValLike};
use nix::sys::timerfd::{ClockId, Expiration, TimerFd, TimerFlags, TimerSetTimeFlags};
use socket2::{Domain, SockAddr, Socket, Type};
use tun_tap::{Iface, Mode};

const GRE_PROTOCOL: i32 = 47;

const TUN_IOC_MAGIC: u8 = b'T';
const TUN_IOC_TUNSETCARRIER: u8 = 226;
ioctl_write_ptr!(
    ioctl_tun_set_carrier,
    TUN_IOC_MAGIC,
    TUN_IOC_TUNSETCARRIER,
    i32
);

fn tun_set_carrier(tun: &Iface, carrier: bool) -> Result<()> {
    let fd = tun.as_raw_fd();
    let carrier = carrier.into();
    unsafe {
        ioctl_tun_set_carrier(fd, &carrier)?;
    }
    Ok(())
}

pub struct TunnelConfig {
    local: Option<Ipv4Addr>,
    remote: Ipv4Addr,
    tunnel_id: u16,
    tap_name: Option<String>,
    keepalive_interval: Option<u64>,
    recv_timeout: Option<u64>,
}

impl TunnelConfig {
    pub fn new(
        local: Option<Ipv4Addr>,
        remote: Ipv4Addr,
        tunnel_id: u16,
        tap_name: Option<String>,
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

pub struct Eoip {
    config: TunnelConfig,
    remote_sa: SockAddr,
    tap: Iface,
    socket: Socket,
    timer_tx: Option<TimerFd>,
    timer_rx: Option<TimerFd>,
    dead: bool,
}

impl Eoip {
    pub fn new(config: TunnelConfig) -> Result<Self> {
        let tap_name = config.tap_name.as_deref().unwrap_or("");
        let tap = Iface::without_packet_info(tap_name, Mode::Tap)?;
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(GRE_PROTOCOL.into()))?;

        let mut timer_tx = None;
        let mut timer_rx = None;
        let mut dead = false;
        if config.keepalive_interval.is_some() {
            timer_tx = Some(TimerFd::new(ClockId::CLOCK_MONOTONIC, TimerFlags::empty())?);
        }

        if config.recv_timeout.is_some() {
            timer_rx = Some(TimerFd::new(ClockId::CLOCK_MONOTONIC, TimerFlags::empty())?);
            dead = true;
        }

        let remote_sa = SockAddr::from(SocketAddrV4::new(config.remote, 0));

        Ok(Eoip {
            config,
            remote_sa,
            tap,
            socket,
            timer_tx,
            timer_rx,
            dead,
        })
    }

    pub fn run(&mut self) -> ! {
        match self._run() {
            Ok(_) => exit(0),
            Err(e) => {
                eprintln!("{}", e);
                exit(1)
            }
        }
    }

    fn _run(&mut self) -> Result<()> {
        eprintln!("Running on {}", self.tap.name());

        // Consider moving this to new()
        if let Some(local) = self.config.local {
            self.socket
                .bind(&SockAddr::from(SocketAddrV4::new(local, 0)))?;
        }

        if let Some(tfd) = &self.timer_tx {
            tfd.set(
                Expiration::Interval(TimeSpec::seconds(
                    self.config.keepalive_interval.unwrap() as i64
                )),
                TimerSetTimeFlags::empty(),
            )?;
            self.send_keepalive()?;
        }

        if self.dead {
            tun_set_carrier(&self.tap, false)?;
        }

        let mut read_fds = FdSet::new();
        loop {
            read_fds.insert(self.tap.as_raw_fd());
            read_fds.insert(self.socket.as_raw_fd());

            if let Some(ref tfd) = self.timer_tx {
                read_fds.insert(tfd.as_raw_fd());
            }

            if let Some(ref tfd) = self.timer_rx {
                read_fds.insert(tfd.as_raw_fd());
            }

            select(None, &mut read_fds, None, None, None)?;

            if read_fds.contains(self.tap.as_raw_fd()) {
                let mut buf = vec![0u8; 65536];
                match self.tap.recv(&mut buf[8..]) {
                    Ok(n) => match self.process_from_tap(n, &mut buf[..n + 8]) {
                        Err(ref e) => eprintln!("process_from_tap: {:#}", e),
                        Ok(_) => {}
                    },
                    Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => panic!("tap.recv: {}", e),
                };
            }
            if read_fds.contains(self.socket.as_raw_fd()) {
                let mut buf = vec![0u8; 65536];
                match self.socket.read(buf.as_mut_slice()) {
                    Ok(n) => {
                        match self.process_from_sock(&buf[..n]) {
                            Err(ref e) => eprintln!("process_from_sock: {:#}", e),
                            Ok(_) => {}
                        };
                    }
                    Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => panic!("socket.read: {}", e),
                };
            }
            if let Some(ref tfd) = self.timer_tx {
                if read_fds.contains(tfd.as_raw_fd()) {
                    tfd.wait()?;
                    self.send_keepalive()?;
                }
            }
            if let Some(ref tfd) = self.timer_rx {
                if read_fds.contains(tfd.as_raw_fd()) {
                    tfd.wait()?;
                    self.dead = true;
                    tun_set_carrier(&self.tap, false)?;
                }
            }
        }
    }

    fn send_keepalive(&mut self) -> Result<()> {
        let mut buf = [32, 1, 100, 0, 0, 0, 0, 0];
        buf[6..8].copy_from_slice(&(self.config.tunnel_id as u16).to_le_bytes());
        self.socket.send_to(&buf, &self.remote_sa)?;
        Ok(())
    }

    fn keepalive_rcvd(&mut self) -> Result<()> {
        if let Some(ref t) = self.timer_rx {
            if self.dead == true {
                tun_set_carrier(&self.tap, true)?;
                self.dead = false;
            }
            t.set(
                Expiration::OneShot(TimeSpec::seconds(self.config.recv_timeout.unwrap() as i64)),
                TimerSetTimeFlags::empty(),
            )?;
        }
        Ok(())
    }

    fn process_from_tap(&mut self, length: usize, buf: &mut [u8]) -> Result<()> {
        if self.dead {
            return Ok(());
        }
        buf[..4].copy_from_slice(&[32, 1, 100, 0]);
        buf[4..6].copy_from_slice(&(length as u16).to_be_bytes());
        buf[6..8].copy_from_slice(&(self.config.tunnel_id as u16).to_le_bytes());
        self.socket.send_to(&buf, &self.remote_sa)?;
        Ok(())
    }

    fn process_from_sock(&mut self, packet: &[u8]) -> Result<()> {
        if packet.len() < 28 {
            return Err(anyhow!("Too short packet received!"));
        }
        let _ip_hdr = &packet[0..19];
        let gre_hdr = &packet[20..24];
        if &gre_hdr[2..] != &[0x64, 0x00] {
            // type not mikrotik eoip
            return Ok(());
        }
        if &gre_hdr[..2] != &[0x20, 0x01] {
            return Err(anyhow!("Unexpected GRE flags: {:?}", &gre_hdr[..2]));
        }
        let tunnel_id = u16::from_le_bytes(packet[26..28].try_into().unwrap());
        if tunnel_id != self.config.tunnel_id {
            return Ok(());
        }
        let data_len_header = u16::from_be_bytes(packet[24..26].try_into().unwrap()) as usize;
        let data_len = packet.len() - 20 - 8;
        if data_len_header != data_len {
            return Err(anyhow!("Data length mismatch!"));
        }
        self.keepalive_rcvd().context("keepalive_rcvd")?;
        if data_len == 0 {
            return Ok(());
        }
        let data = &packet[28..];
        match self.tap.send(data) {
            Ok(_) => Ok(()),
            Err(ref e) if matches!(e.raw_os_error(), Some(5)) => Ok(()),
            Err(e) => Err(anyhow!("Failed to send to TAP interface: {}", e)),
        }
    }
}
