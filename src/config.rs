//! Configuration parameters for the TA->Asterisk sync

use std::{
    fs::File,
    io::BufReader,
    net::{IpAddr, TcpStream},
    path::Path,
    sync::Arc,
};

use rustls::{pki_types::TrustAnchor, ClientConfig, ClientConnection};
use serde::Deserialize;
use smol::net::UdpSocket;
use tracing::{debug, error, event, trace, Level};

use crate::ami::{AmiConnection, AmiError};

#[derive(Debug)]
pub struct Config {
    pub cmi: CmiConfig,
    pub asterisk: AsteriskConfig,
}
impl TryFrom<ConfigData> for Config {
    type Error = core::net::AddrParseError;
    fn try_from(value: ConfigData) -> Result<Self, Self::Error> {
        Ok(Self {
            cmi: value.cmi.try_into()?,
            asterisk: value.asterisk,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct ConfigData {
    pub cmi: CmiConfigData,
    pub asterisk: AsteriskConfig,
}

#[derive(Debug)]
pub struct CmiConfig {
    /// listen on this address
    pub listen_addr: IpAddr,
    /// Expect the packet to arrive from this address. Ignore all other packets.
    pub expect_from_addr: IpAddr,
    /// expect this CAN-ID in messages we get (ignore others)
    pub expect_index: u8,
    /// expect this PDO in messages we get (ignore others)
    pub expect_pdo: u8,
    /// IF true:
    /// expect the value ON to be sent; iff OFF is sent (circuit open), originate a call
    /// IF false:
    /// expect the value OFF to be sent; iff ON is sent (circuit closed), originate a call
    pub circuit_is_normally_closed: bool,
}
impl TryFrom<CmiConfigData> for CmiConfig {
    type Error = core::net::AddrParseError;
    fn try_from(value: CmiConfigData) -> Result<Self, Self::Error> {
        Ok(Self {
            listen_addr: value.listen_addr.parse()?,
            expect_from_addr: value.expect_from_addr.parse()?,
            expect_index: value.expect_index,
            expect_pdo: value.expect_pdo,
            circuit_is_normally_closed: value.circuit_is_normally_closed,
        })
    }
}

/// The config for listening for messages from a CMI
#[derive(Debug, Deserialize)]
pub struct CmiConfigData {
    /// listen on this address
    pub listen_addr: String,
    /// Expect the packet to arrive from this address. Ignore all other packets.
    pub expect_from_addr: String,
    /// expect this CAN-ID in messages we get (ignore others)
    pub expect_index: u8,
    /// expect this PDO in messages we get (ignore others)
    pub expect_pdo: u8,
    pub circuit_is_normally_closed: bool,
}

/// Configuration for the interaction with Asterisk.
#[derive(Debug, Deserialize)]
pub struct AsteriskConfig {
    /// The host to make calls to.
    pub host: String,
    /// The port to make calls to.
    /// Default: 5038
    pub port: Option<u16>,
    /// The contexet to send a call in.
    pub execute_context: String,
    /// The extension to call.
    pub execute_exten: String,
    /// The priority to start execution at in the given extension.
    /// Default: "1"
    pub execute_priority: Option<String>,
    /// In addition to global certs, also trust the CAs in this pem file
    pub trust_extra_pem: Option<String>,
    /// use to login to asterisk
    pub username: String,
    pub secret: String,
    pub call_external_endpoints: Vec<String>,
    pub caller_id: String,
}

impl Config {
    pub fn create() -> Result<Self, Box<dyn std::error::Error>> {
        let config_path = Path::new("/etc/ta-asterisk-alarm/config.yaml");
        let f = match File::open(config_path) {
            Ok(x) => x,
            Err(e) => {
                event!(
                    Level::ERROR,
                    "config file /etc/asterconf/config.yaml not readable: {e}"
                );
                return Err(Box::new(e));
            }
        };
        let config_data: ConfigData = match serde_yaml::from_reader(f) {
            Ok(x) => x,
            Err(e) => {
                event!(Level::ERROR, "config file had syntax errors: {e}");
                return Err(Box::new(e));
            }
        };
        Ok(config_data.try_into()?)
    }

    /// create the UDP socket required
    pub async fn cmi_listen_socket(&self) -> Result<UdpSocket, std::io::Error> {
        UdpSocket::bind(format!("{}:5442", self.cmi.listen_addr)).await
    }

    /// load additional certs if required by the config
    fn additional_certs(&self) -> Result<Vec<TrustAnchor<'static>>, Box<dyn std::error::Error>> {
        if let Some(pemfile) = &self.asterisk.trust_extra_pem {
            // read pem file given in the file given in the config
            let reader = std::fs::File::open(pemfile)?;
            let mut res = Vec::<TrustAnchor<'static>>::new();
            for der_obj in rustls_pemfile::certs(&mut BufReader::new(reader)) {
                match der_obj {
                    Ok(cert) => {
                        res.push(webpki::anchor_from_trusted_cert(&cert)?.to_owned());
                    }
                    Err(e) => {
                        return Err(e)?;
                    }
                }
            }
            Ok(res)
        } else {
            Ok(std::vec::Vec::<TrustAnchor<'static>>::new())
        }
    }

    /// prepare the stream to talk to asterisk with
    pub fn asterisk_connection(&self) -> Result<AmiConnection, Box<dyn std::error::Error>> {
        debug!("Trying to connect to Asterisk AMI. Make sure asterisk is reachable if this hangs!");
        // setup rustls config (used for TCP stream with asterisk)
        let asterisk_tcp = match TcpStream::connect(format!(
            "{}:{}",
            self.asterisk.host,
            self.asterisk.port.unwrap_or(5039)
        )) {
            Ok(x) => x,
            Err(e) => {
                error!(
                    "Unable to start TCP socket on {}:{} : {e}",
                    self.asterisk.host,
                    self.asterisk.port.unwrap_or(5039)
                );
                Err(e)?
            }
        };

        let mut roots: Vec<TrustAnchor> = webpki_roots::TLS_SERVER_ROOTS.into();
        let add_certs = match self.additional_certs() {
            Ok(x) => x,
            Err(e) => {
                error!(
                    "Unable to load additional certs from {:?}: {e}",
                    self.asterisk.trust_extra_pem
                );
                Err(e)?
            }
        };
        roots.extend(add_certs);
        let root_store = rustls::RootCertStore { roots };
        let tls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        // TLS stream to asterisk
        let asterisk_conn = match ClientConnection::new(
            Arc::new(tls_config),
            self.asterisk.host.clone().try_into()?,
        ) {
            Ok(x) => x,
            Err(e) => {
                error!("Unable to create a TLS client connection: {e}");
                Err(e)?
            }
        };
        let mut conn = AmiConnection::new(rustls::StreamOwned::new(asterisk_conn, asterisk_tcp));

        let version = conn.read_version_line()?;
        trace!("Was able to get this version from ami: {version}.");
        let command = format!(
            "Action: Login\r\nAuthType: plain\r\nUsername: {}\r\nSecret: {}\r\nEvents: off\r\n\r\n",
            self.asterisk.username, self.asterisk.secret
        );
        let response = conn.send_action(command)?;
        let success = response.lines().any(|l| l.starts_with("Response: Success"));

        if success {
            trace!("Login was acknowledged.");
            Ok(conn)
        } else {
            Err(AmiError::LoginFailure)?
        }
    }
}
