use std::io::Write;
use std::net::SocketAddr;

use coe::Packet;
use config::Config;
use tracing::level_filters::LevelFilter;
use tracing::{debug, info, trace, warn};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::prelude::*;

mod config;

/// Send the AMI command to asterisk.
fn send_ami_command(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let mut asterisk_stream = config.asterisk_stream()?;

    let priority = if let Some(x) = &config.asterisk.execute_priority {
        x
    } else {
        "1"
    };
    let command = format!(
        "Action: Originate\r\nExten: {}\r\nContext: {}\r\nPriority: {}\r\n\r\n",
        config.asterisk.execute_exten, config.asterisk.execute_context, priority,
    );
    asterisk_stream.write(command.as_bytes())?;
    Ok(())
}

/// Process a single UDP packet, potentially calling to asterisk.
fn packet_is_alarm(
    config: &Config,
    buf: &[u8],
    remote: SocketAddr,
) -> Result<bool, Box<dyn std::error::Error>> {
    // check if we want to receive packets from the remote
    if remote.ip() != config.cmi.expect_from_addr {
        trace!(
            "Got a COE payload, but ignoring it does not come from {}",
            config.cmi.expect_from_addr
        );
        // silently ignore packets from the wrong IP
        return Ok(false);
    };
    // try to parse the packet
    let packet: Packet = buf.try_into()?;
    // ignore packets to the wrong ID or PDO
    'payload: for payload in packet {
        if payload.node() != config.cmi.expect_index {
            trace!(
                "Got a COE payload, but ignoring it because the CAN-ID is not {}",
                config.cmi.expect_index
            );
            continue 'payload;
        };
        if payload.pdo_index() != config.cmi.expect_pdo {
            trace!(
                "Got a COE payload, but ignoring it because the pdo index is not {}",
                config.cmi.expect_pdo
            );
            continue 'payload;
        };
        // we have a packet to the correct CAN-ID and PDO, from the correct Address
        // ignore it if it is not digital.
        match payload.value() {
            coe::COEValue::Digital(coe::DigitalCOEValue::OnOff(true)) => {
                // this is a relevant packet. send the command to ami
                return Ok(true);
            }
            _ => {
                info!("Got a COE packet, but ignoring it because the value is not DigitalOnOff, with value ON.");
                return Ok(false);
            }
        }
    }
    debug!("Got a COE packet, but no payload was relevant.");
    Ok(false)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // setup tracing
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .compact()
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .with_line_number(true)
            .with_filter(LevelFilter::TRACE),
    );
    tracing::subscriber::set_global_default(subscriber).expect("static tracing config");

    // setup config
    let config = Config::create()?;

    // UDP socket listening for CMI input
    let cmi_listen_socket = config.cmi_listen_socket()?;
    // force the opening of a TLS stream. This makes error messages available immediately on
    // startup.
    let _ = config.asterisk_stream()?;

    info!(
        "Got config and UDP socket. Now listening for COE packets on {}",
        cmi_listen_socket.local_addr()?
    );
    loop {
        let mut buf = [0_u8; 252];
        match cmi_listen_socket.recv_from(&mut buf) {
            Ok((len, addr)) => {
                trace!("Received UDP packet of {len} bytes on CMI listen socket.");
                // We have a relevant packet. Process it.
                match packet_is_alarm(&config, &buf, addr) {
                    Ok(false) => {
                        debug!("Correctly handled a single UDP packet from the CMI.");
                    }
                    Ok(true) => match send_ami_command(&config) {
                        Ok(()) => info!("Correctly send a command to asterisk."),
                        Err(e) => warn!(
                            "Tried to send an AMI command to asterisk, but got this error: {e}"
                        ),
                    },
                    Err(e) => {
                        warn!("Error while processing packet: {e}");
                    }
                };
            }
            Err(e) => {
                warn!("Error receiving UDP packet on CMI listen socket: {e}.");
            }
        };
    }
}
