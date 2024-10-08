use std::net::SocketAddr;
use std::sync::atomic::AtomicU32;

use coe::Packet;
use config::Config;
use smol::net::UdpSocket;
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::{prelude::*, EnvFilter};

mod ami;
mod config;

/// Send the AMI command to asterisk.
fn send_ami_command(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let mut ami_conn = config.asterisk_connection()?;

    let priority = if let Some(x) = &config.asterisk.execute_priority {
        x
    } else {
        "1"
    };
    for external_number in &config.asterisk.call_external_endpoints {
        let command = format!(
            "Action: Originate\r\nExten: {}\r\nContext: {}\r\nPriority: {}\r\nChannel: {}\r\nCallerID: {}\r\nAsync: true\r\n\r\n",
            config.asterisk.execute_exten, config.asterisk.execute_context, priority,
            external_number, config.asterisk.caller_id,
        );
        match ami_conn.send_action(command) {
            Ok(response) => debug!("Got this response from asterisk: {response}."),
            Err(e) => warn!(
                "Error sending Command to asterisk for external number {external_number}: {e}."
            ),
        }
    }
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
            "Got a COE payload, but ignoring it because it does not come from {}",
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
        // NOTE: shift the index by +1; date on-wire is one lower then data entered in CMIs web-gui
        if payload.pdo_index() + 1 != config.cmi.expect_pdo {
            trace!(
                "Got a COE payload, but ignoring it because the pdo index is not {}",
                config.cmi.expect_pdo
            );
            continue 'payload;
        };
        // we have a packet to the correct CAN-ID and PDO, from the correct Address
        // ignore it if it is not digital.
        match payload.value() {
            // Originate an alarm iff:
            // IF the circuit is_normally_closed, we alarm when false is sent
            // IF the circuit IS NOT is_normally_closed, we alarm when true is sent
            coe::COEValue::Digital(coe::DigitalCOEValue::OnOff(x)) => {
                if x == config.cmi.circuit_is_normally_closed {
                    trace!("Got correctly formed value from the expected IP/Node/PDO. Value is {x}, which is the no-alarm state.");
                    return Ok(false);
                } else {
                    return Ok(true);
                }
            }
            _ => {
                trace!("Got value from the expected IP/NODE/PDO, but ignoring it because the value is not DigitalOnOff.");
                return Ok(false);
            }
        };
    }
    debug!("Got a COE packet, but no payload was relevant.");
    Ok(false)
}

async fn handle_packet(config: &Config, cmi_listen_socket: &UdpSocket, buf: &mut [u8], alarm_sent_counter: &AtomicU32) {
    match cmi_listen_socket.recv_from(buf).await {
        Ok((len, addr)) => {
            trace!("Received UDP packet of {len} bytes on CMI listen socket.");
            // We have a relevant packet. Process it.
            match packet_is_alarm(config, &buf[0..len], addr) {
                Ok(false) => {
                    // reset the alarm repeat count
                    alarm_sent_counter.store(0, std::sync::atomic::Ordering::Relaxed);
                    trace!("Correctly handled a single UDP packet from the CMI.");
                }
                Ok(true) => {
                    // check if we have already sent the alarm to many times
                    let send_command = if let Some(max_nr_of_repeats) = config.asterisk.repeat_alarm {
                        max_nr_of_repeats >= alarm_sent_counter.load(std::sync::atomic::Ordering::Relaxed)
                    } else {
                        true
                    };
                    if send_command {
                        match send_ami_command(config) {
                            Ok(()) => {
                                alarm_sent_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                info!("Alarm received, all commands send to asterisk successfully.");
                            }
                            Err(e) => {
                                warn!("Tried to send AMI commands to asterisk, but got this error: {e}");
                            }
                        }
                    } else {
                        info!("Received an Alarm, but I have already called the max number of times.")
                    }
                },
                Err(e) => {
                    warn!("Error while processing incoming UDP packet: {e}");
                }
            };
        }
        Err(e) => {
            warn!("Error receiving UDP packet on CMI listen socket: {e}.");
        }
    };
}

async fn shutdown(shutdown_chan: &smol::channel::Receiver<()>) {
    match shutdown_chan.recv().await {
        Ok(()) => {
            info!("Shutting down.");
            std::process::exit(0);
        }
        Err(e) => {
            warn!("Error while receiving shutdown signal: {e}. Shutting down.");
            std::process::exit(1);
        }
    };
}

async fn main_loop(
    config: &Config,
    cmi_listen_socket: UdpSocket,
    shutdown_chan: &smol::channel::Receiver<()>,
) {
    let mut buf = [0_u8; 252];
    // tracks how many times we have already sent the alarm
    let alarm_sent_counter = AtomicU32::new(0);
    // This is the main loop: receive UDP; process and potentially send commands to AMI.
    // Does not break outside of a potential panic.
    #[allow(clippy::infinite_loop)]
    loop {
        smol::future::race(
            shutdown(shutdown_chan),
            handle_packet(config, &cmi_listen_socket, &mut buf, &alarm_sent_counter),
        )
        .await;
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // setup tracing
    let my_crate_filter = EnvFilter::new("ta_asterisk_alarm");
    let subscriber = tracing_subscriber::registry().with(my_crate_filter).with(
        tracing_subscriber::fmt::layer()
            .compact()
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .with_line_number(true)
            .with_filter(LevelFilter::TRACE),
    );
    tracing::subscriber::set_global_default(subscriber).expect("static tracing config");

    let (tx, rx) = smol::channel::bounded(1);
    ctrlc::set_handler(move || {
        smol::block_on(async {
            tx.send(()).await.expect("Could not send shutdown message.");
        })
    })
    .expect("Could not install signal handler.");

    // setup config
    let config = Config::create()?;

    // UDP socket listening for CMI input
    let cmi_listen_socket = smol::block_on(config.cmi_listen_socket())?;
    // force the opening of a TLS stream. This makes error messages available immediately on
    // startup.
    let ami_conn = config.asterisk_connection();
    match ami_conn {
        Ok(_conn) => info!("Connection to asterisk could be established."),
        Err(e) => {
            error!("Unable to connect to asterisk: {e}");
            Err(e)?;
        }
    };

    info!(
        "Got UDP socket and made sure that asterisk is reachable. Now listening for COE packets on {}",
        cmi_listen_socket.local_addr()?
    );
    smol::block_on(main_loop(&config, cmi_listen_socket, &rx));
    Ok(())
}
