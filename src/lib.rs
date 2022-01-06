//! Checks SSL certificate expiration.
//!
//! This crate will try to connect a remote server and check SSL certificate expiration.
//!
//! Example:
//!
//! ```rust
//! use ssl_expiration::SslExpiration;
//!
//! let expiration = SslExpiration::from_domain_name("google.com").unwrap();
//! if expiration.is_expired() {
//!     // do something if SSL certificate expired
//! }
//! ```

extern crate openssl;
#[macro_use]
extern crate error_chain;

use std::net::{TcpStream, ToSocketAddrs};
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};
use openssl::asn1::Asn1Time;
use error::Result;

pub struct SslExpiration {
    secs: i32,
    alt_names: Vec<String>
}


impl SslExpiration {
    /// Creates new SslExpiration from domain name.
    ///
    /// This function will use HTTPS port (443) to check SSL certificate.
    pub fn from_domain_name(domain: &str) -> Result<SslExpiration> {
        SslExpiration::from_addr(format!("{}:443", domain))
    }

    /// Creates new SslExpiration from SocketAddr.
    pub fn from_addr<A: ToSocketAddrs>(addr: A) -> Result<SslExpiration> {
        let context = {
            let mut context = SslContext::builder(SslMethod::tls())?;
            context.set_verify(SslVerifyMode::empty());
            context.build()
        };
        let connector = Ssl::new(&context)?;
        let stream = TcpStream::connect(addr)?;
        let stream = connector.connect(stream)
            .map_err(|e| error::ErrorKind::HandshakeError(e.to_string()))?;
        let cert = stream.ssl()
            .peer_certificate()
            .ok_or("Certificate not found")?;

        let mut alt_names = vec![];
        if let Some(names) = cert.subject_alt_names() {
            alt_names = names.iter()
                .filter_map(|n| n.dnsname()).map(|n| n.to_string())
                .collect();
        }

        let now = Asn1Time::days_from_now(0)?;
        let from_now = now.diff(cert.not_after())?;

        cert.verify(&cert.public_key().expect("Public Key Missing"))
            .expect("Cert verified");

        Ok(SslExpiration { secs: from_now.days * 24 * 60 * 60 + from_now.secs, alt_names })
    }

    /// How many seconds until SSL certificate expires.
    ///
    /// This function will return minus if SSL certificate is already expired.
    pub fn secs(&self) -> i32 {
        self.secs
    }

    /// How many days until SSL certificate expires
    ///
    /// This function will return minus if SSL certificate is already expired.
    pub fn days(&self) -> i32 {
        self.secs / 60 / 60 / 24
    }

    /// Returns true if SSL certificate is expired
    pub fn is_expired(&self) -> bool {
        self.secs < 0
    }

    pub fn get_alt_names(&self) -> &Vec<String> {
        &self.alt_names
    }
}



pub mod error {
    use std::io;
    use openssl;

    error_chain! {
        foreign_links {
            OpenSslErrorStack(openssl::error::ErrorStack);
            IoError(io::Error);
        }
        errors {
            HandshakeError(e: String) {
                description("HandshakeError")
                display("HandshakeError: {}", e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ssl_expiration() {
        assert!(!SslExpiration::from_domain_name("google.com").unwrap().is_expired());
        // See: https://www.ssl.com/sample-valid-revoked-and-expired-ssl-tls-certificates/
        assert!(SslExpiration::from_domain_name("expired-rsa-dv.ssl.com").unwrap().is_expired());
        // TODO: Add test for revoked certificates
        assert!(SslExpiration::from_domain_name("revoked-rsa-dv.ssl.com").unwrap().is_expired());
    }
}
