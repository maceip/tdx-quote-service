use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Buf, Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use intel_tee_quote_verification_rs::*;
use intel_tee_quote_verification_sys as qvl_sys;
use pki_types::{CertificateDer, PrivateKeyDer};
use rand::Rng;
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::{env, fs, io};
use tdx_attest_rs;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
pub const REPORT_DATA_SIZE: usize = 64;

fn main() {
    if let Err(e) = run_server() {
        eprintln!("FAILED: {}", e);
        std::process::exit(1);
    }
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

#[tokio::main]
async fn run_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Set a process wide default crypto provider.
    #[cfg(feature = "ring")]
    let _ = rustls::crypto::ring::default_provider().install_default();
    #[cfg(feature = "aws-lc-rs")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // First parameter is port number (optional, defaults to 1337)
    let port = match env::args().nth(1) {
        Some(ref p) => p.parse()?,
        None => 1337,
    };
    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);

    // Load public certificate.
    let certs = load_certs("fixture/sample.pem")?;
    // Load private key.
    let key = load_private_key("fixture/sample.rsa")?;

    println!("tdx-quote-service running on https://{}", addr);

    // Create a TCP listener via tokio.
    let incoming = TcpListener::bind(&addr).await?;

    // Build TLS configuration.
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| error(e.to_string()))?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    let service = service_fn(echo);

    loop {
        let (tcp_stream, _remote_addr) = incoming.accept().await?;

        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => tls_stream,
                Err(err) => {
                    eprintln!("failed to perform tls handshake: {err:#}");
                    return;
                }
            };
            if let Err(err) = Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls_stream), service)
                .await
            {
                eprintln!("failed to serve connection: {err:#}");
            }
        });
    }
}

async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let mut response = Response::new(Full::default());
    let mut collateral_expiration_status = 1u32;
    let mut quote_verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;

    let mut supp_data: sgx_ql_qv_supplemental_t = Default::default();
    let mut supp_data_desc = tee_supp_data_descriptor_t {
        major_version: 0,
        data_size: 0,
        p_data: &mut supp_data as *mut sgx_ql_qv_supplemental_t as *mut u8,
    };

    match (req.method(), req.uri().path()) {
        // Help route.
        (&Method::POST, "/quote") => {
            let mut whole_body = req
                .into_body()
                .collect()
                .await?
                .aggregate();

            // Ensure that the body is the correct size for tdx_report_data_t
            if whole_body.remaining() != 64 {
                *response.status_mut() = StatusCode::BAD_REQUEST;
            }

            // Convert the body into tdx_report_data_t
            let mut report_data_bytes = [0u8; 64];
            whole_body.copy_to_slice(&mut report_data_bytes);
            let report_data = tdx_attest_rs::tdx_report_data_t {
                d: report_data_bytes,
            };

            let mut tdx_report = tdx_attest_rs::tdx_report_t { d: [0; 1024usize] };
            let result = tdx_attest_rs::tdx_att_get_report(Some(&report_data), &mut tdx_report);
            let mut selected_att_key_id = tdx_attest_rs::tdx_uuid_t { d: [0; 16usize] };
            let (result, quote) = tdx_attest_rs::tdx_att_get_quote(
                Some(&report_data),
                None,
                Some(&mut selected_att_key_id),
                0,
            );

            if result != tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS {
                println!("Failed to get the quote.");
                *response.status_mut() = StatusCode::NOT_FOUND;
            }
            match quote {
                Some(q) => {
                    println!("TDX quote data: {:?}", q);
                    println!("Successfully get the TD Quote.");
                    *response.body_mut() = Full::from(q);
                }
                None => {
                    *response.status_mut() = StatusCode::NOT_FOUND;
                }
            }
        }
        // todo
        (&Method::POST, "/verify") => {
            let mut whole_body = req
                .into_body()
                .collect()
                .await?
                .aggregate();

            // Ensure that the body is the correct size for tdx_report_data_t
            if whole_body.remaining() != 8000 {
                *response.status_mut() = StatusCode::BAD_REQUEST;
            }

            // Convert the body into tdx_report_data_t
            let mut user_quote = [0u8; 8000];
            whole_body.copy_to_slice(&mut user_quote);

            let collateral = tee_qv_get_collateral(&user_quote);
            let current_time = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs() as i64;

            match tee_verify_quote(
                &user_quote,
                collateral.ok().as_ref(),
                current_time,
                None,
                None,
            ) {
                Ok((colla_exp_stat, qv_result)) => {
                    collateral_expiration_status = colla_exp_stat;
                    quote_verification_result = qv_result;
                    println!("\tInfo: App: tee_verify_quote successfully returned.");
                    *response.body_mut() = Full::from(colla_exp_stat.to_string());
                }
                Err(e) => println!("\tError: App: tee_verify_quote failed: {:#04x}", e as u32),
            }
        }
        // Catch-all 404.
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    };
    Ok(response)
}

// Load public certificate from file.
fn load_certs(filename: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    // Open certificate file.
    let certfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    rustls_pemfile::certs(&mut reader).collect()
}

// Load private key from file.
fn load_private_key(filename: &str) -> io::Result<PrivateKeyDer<'static>> {
    // Open keyfile.
    let keyfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);

    // Load and return a single private key.
    rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())
}
