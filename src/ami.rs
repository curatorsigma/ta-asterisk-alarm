//! Handles reading of packets from ami

use std::{
    io::{Read, Write},
    net::TcpStream,
};

use rustls::{ClientConnection, StreamOwned};
use tracing::warn;

/// Everything that can go wrong in an AMI connection
#[derive(Debug)]
pub enum AmiError {
    /// unable to read bytes from stream
    Read(std::io::Error),
    /// unable to read bytes from stream
    Write(std::io::Error),
    /// \n without precding \r
    IsolatedNewline,
    /// Bytes were not UTF-8
    NotUtf8(std::str::Utf8Error),
    /// \0 without \n before it
    EofBeforeNeline,
    /// There was not Response: Line sent but one was expected.
    NoResponseLine,
    /// Action was executed, and response received, but Response: Success was not send.
    ActionUnsuccessful,
    /// Login was attempted but failed.
    LoginFailure,
}
impl core::fmt::Display for AmiError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Read(x) => write!(f, "Unable to read bytes from stream: {x}"),
            Self::Write(x) => write!(f, "Unable to write bytes to stream: {x}"),
            Self::IsolatedNewline => write!(f, "A \\n was encountered without a preceding \\r"),
            Self::NotUtf8(x) => write!(f, "The received bytes were not utf8: {x}"),
            Self::EofBeforeNeline => write!(f, "There was a nullbyte before an expected newline"),
            Self::NoResponseLine => write!(f, "There was no Response: line, but one was expected."),
            Self::ActionUnsuccessful => write!(
                f,
                "Action was sent and response received, but the response was not Success."
            ),
            Self::LoginFailure => write!(f, "Login was attempted but failed."),
        }
    }
}
impl From<std::str::Utf8Error> for AmiError {
    fn from(value: std::str::Utf8Error) -> Self {
        Self::NotUtf8(value)
    }
}
impl std::error::Error for AmiError {}

pub struct AmiConnection {
    stream: StreamOwned<ClientConnection, TcpStream>,
    buffer: String,
}
impl AmiConnection {
    pub fn new(stream: StreamOwned<ClientConnection, TcpStream>) -> Self {
        Self {
            stream,
            buffer: String::new(),
        }
    }

    /// Read the first line from an AMI stream.
    /// In that line, asterisk will push its Version number.
    ///
    /// Returns:
    /// - The Version line, if everything was successful.
    /// - AmiError, if reading failed or the read values are not utf8-parsable.
    pub fn read_version_line(&mut self) -> Result<String, AmiError> {
        const VERSION_LINE_BUF_LEN: usize = 128;
        let mut buf = [0_u8; VERSION_LINE_BUF_LEN];

        let mut version_line = String::new();

        loop {
            let bytes_read = self.stream.read(&mut buf).map_err(AmiError::Read)?;
            if bytes_read == 0 {
                continue;
            };
            let first_nullbyte = buf.iter().position(|x| *x == 0);
            // seek to the first \n
            if let Some(idx) = buf.iter().position(|x| *x == '\n' as u8) {
                if idx == 0 || buf[idx - 1] != '\r' as u8 {
                    return Err(AmiError::IsolatedNewline);
                }
                // the spec does not say how the first line is supposed to look like..
                // so we just ignore the first line completely
                // but we need to check that they are actually utf-8 first
                version_line.push_str(std::str::from_utf8(&buf[0..=idx - 1])?);
                self.buffer.push_str(std::str::from_utf8(
                    &buf[idx + 1..first_nullbyte.unwrap_or(VERSION_LINE_BUF_LEN)],
                )?);
                return Ok(version_line);
            } else if first_nullbyte == None {
                version_line.push_str(std::str::from_utf8(&buf)?);
            } else {
                return Err(AmiError::EofBeforeNeline);
            }
        }
    }

    /// Read the next response (blocking)
    ///
    /// On Error, the internal buffer is reset. It may be impossible to recover from this.
    pub fn read_next_response(&mut self) -> Result<String, AmiError> {
        const MESSAGE_BUF_LEN: usize = 256;
        let mut buf = [0_u8; MESSAGE_BUF_LEN];

        loop {
            let bytes_read = self.stream.read(&mut buf).map_err(AmiError::Read)?;
            if bytes_read == 0 {
                continue;
            };
            let first_nullbyte = buf.iter().position(|x| *x == 0);
            // convert bytes to utf-8
            let as_str =
                match std::str::from_utf8(&buf[..first_nullbyte.unwrap_or(MESSAGE_BUF_LEN)]) {
                    Ok(x) => x,
                    Err(e) => {
                        self.buffer.clear();
                        return Err(e)?;
                    }
                };
            if let Some(first_double_crlf_pos) = as_str.find("\r\n\r\n") {
                self.buffer.push_str(&as_str[..first_double_crlf_pos + 2]);
                // self.buffer now contains the entire Message we care about (minus the last \r\n
                // which carry no semantics since they occur at the end of a Message where they are
                // mandatory by the Protocol)

                // We now return self.buffer and set it to an empty string
                let mut new_buf = String::new();
                core::mem::swap(&mut new_buf, &mut self.buffer);
                return Ok(new_buf);
            } else {
                self.buffer.push_str(as_str);
                continue;
            };
        }
    }

    /// Send an action to the Server and read the next response.
    pub fn send_action(&mut self, action: String) -> Result<String, AmiError> {
        self.stream
            .write(action.as_bytes())
            .map_err(AmiError::Write)?;
        self.read_next_response()
    }
}
/// Logoff before closing the TcpStream
impl Drop for AmiConnection {
    fn drop(&mut self) {
        // this can fail because it sends data over a network.
        // we simply ignore the error; if the logoff fails, we will simply want to drop the
        // TcpStream anyways
        match self.send_action("Action: Logoff\r\n\r\n".to_owned()) {
            Ok(_) => {}
            Err(e) => {
                warn!("Unable to logoff before dropping an AmiConnection: {e}.");
            }
        }
    }
}
