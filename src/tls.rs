// Copyright 2023 Turing Machines
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Trust-on-first-use pinning of the BMC's self-signed TLS certificate.
//!
//! The BMC serves a self-signed certificate, so it cannot be verified against
//! a CA. Instead, the certificate seen on the first connection to a host is
//! saved, and later connections must present the exact same certificate.

use std::path::PathBuf;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};

use crate::request::host_file_name;

/// Returns a TLS config that pins the certificate of `host`, or `None` if
/// there is nowhere to store the pinned certificate.
pub fn pinned_client_config(host: &str) -> anyhow::Result<Option<ClientConfig>> {
    let Some(dir) = dirs::data_local_dir() else {
        return Ok(None);
    };

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = PinnedCert {
        path: dir.join(host_file_name("tpi_cert", host)),
        provider: provider.clone(),
    };
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    Ok(Some(config))
}

#[derive(Debug)]
struct PinnedCert {
    path: PathBuf,
    provider: Arc<CryptoProvider>,
}

impl PinnedCert {
    fn verify(&self, cert: &[u8]) -> Result<(), String> {
        let path = self.path.display();
        match std::fs::read(&self.path) {
            Ok(pinned) if pinned == cert => Ok(()),
            Ok(_) => Err(format!(
                "the BMC's TLS certificate has changed since it was first trusted. \
                 This is expected after reflashing the BMC firmware, but could also \
                 mean someone is intercepting the connection. If you trust the new \
                 certificate, delete {path} and try again"
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(dir) = self.path.parent() {
                    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                }
                std::fs::write(&self.path, cert).map_err(|e| format!("{path}: {e}"))?;
                eprintln!("Trusting the BMC's TLS certificate on first use (saved to {path})");
                Ok(())
            }
            Err(e) => Err(format!("{path}: {e}")),
        }
    }
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.verify(end_entity)
            .map(|()| ServerCertVerified::assertion())
            .map_err(Error::General)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_on_first_use() {
        let path = std::env::temp_dir().join(format!("tpi_cert_test_{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let pin = PinnedCert {
            path: path.clone(),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        };

        assert!(pin.verify(b"first").is_ok());
        assert!(pin.verify(b"first").is_ok());
        assert!(pin.verify(b"other").is_err());

        std::fs::remove_file(&path).unwrap();
        assert!(pin.verify(b"other").is_ok());
        std::fs::remove_file(&path).unwrap();
    }
}
