use std::{
    io::{self, Write},
    pin::Pin,
    sync::{Arc, LazyLock},
};

use anyhow::{Context, Result};
use boring::{
    error::ErrorStack,
    ex_data::Index,
    ssl::{
        CertificateCompressionAlgorithm, CertificateCompressor, Ssl, SslContextBuilder, SslMethod,
        SslMode, SslOptions, SslSessionCacheMode, SslVerifyMode, SslVersion,
    },
    version,
    x509::verify::X509CheckFlags,
};
use tokio::net::TcpStream;
use tungstenite::client::IntoClientRequest;

use crate::{
    client::session::{TlsSession, TlsSessionCache},
    ssl::SslStream,
};

pub type WsStream = tokio_tungstenite::WebSocketStream<SslStream<TcpStream>>;

/// Connect to the remote server with a Chrome-like TLS fingerprint and upgrade
/// to WebSocket with browser-realistic HTTP headers.
pub async fn connect(
    server: &str,
    port: u16,
    path: &str,
    sni: &str,
    skip_verify: bool,
    cache: Arc<TlsSessionCache>,
) -> Result<WsStream> {
    let tcp = TcpStream::connect(format!("{server}:{port}"))
        .await
        .with_context(|| format!("TCP connect to {server}:{port}"))?;

    let url = if port == 443 {
        format!("wss://{sni}{path}")
    } else {
        format!("wss://{sni}:{port}{path}")
    };

    let ssl = build_ssl(&url, sni, skip_verify, cache)?;
    let mut ssl_stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut ssl_stream)
        .connect()
        .await
        .context("TLS handshake")?;

    let request = url.into_client_request()?;
    let (ws, _) = tokio_tungstenite::client_async(request, ssl_stream)
        .await
        .context("WebSocket handshake")?;

    Ok(ws)
}

struct BrotliCompressor;

impl CertificateCompressor for BrotliCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    #[inline]
    fn compress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: io::Write,
    {
        let mut writer = brotli::CompressorWriter::new(output, input.len(), 11, 32);
        writer.write_all(input)?;
        writer.flush()?;
        Ok(())
    }

    #[inline]
    fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: io::Write,
    {
        let mut reader = brotli::Decompressor::new(input, 4096);
        io::copy(&mut reader, output)?;
        Ok(())
    }
}

macro_rules! join {
    ($sep:expr, $first:expr $(, $rest:expr)*) => {
        concat!($first $(, $sep, $rest)*)
    };
}

fn key_index() -> Result<Index<Ssl, String>, ErrorStack> {
    static IDX: LazyLock<Result<Index<Ssl, String>, ErrorStack>> = LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

fn build_ssl(url: &str, sni: &str, skip_verify: bool, cache: Arc<TlsSessionCache>) -> Result<Ssl> {
    let mut ctx = SslContextBuilder::new(SslMethod::tls())?;
    let mut opts = SslOptions::ALL
        | SslOptions::NO_COMPRESSION
        | SslOptions::NO_SSLV2
        | SslOptions::NO_SSLV3
        | SslOptions::SINGLE_DH_USE
        | SslOptions::SINGLE_ECDH_USE;
    opts &= !SslOptions::DONT_INSERT_EMPTY_FRAGMENTS;
    ctx.set_options(opts);

    let mut mode =
        SslMode::AUTO_RETRY | SslMode::ACCEPT_MOVING_WRITE_BUFFER | SslMode::ENABLE_PARTIAL_WRITE;
    // This is quite a useful optimization for saving memory, but historically
    // caused CVEs in OpenSSL pre-1.0.1h, according to
    // https://bugs.python.org/issue25672
    if version::number() >= 0x1000_1080 {
        mode |= SslMode::RELEASE_BUFFERS;
    }
    ctx.set_mode(mode);

    ctx.set_default_verify_paths()?;

    if skip_verify {
        ctx.set_verify(SslVerifyMode::NONE);
    } else {
        ctx.set_verify(SslVerifyMode::PEER);
    }

    // Set BROTLI compression algorithm
    ctx.add_certificate_compression_algorithm(BrotliCompressor)?;

    // TLS 1.2–1.3 only (Chrome dropped TLS 1.0/1.1)
    ctx.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    ctx.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    // Set OCSP stapling
    ctx.enable_ocsp_stapling();

    // Set Signed Certificate Timestamps (SCT)
    ctx.enable_signed_cert_timestamps();

    // Set TLS grease options
    // Generate Random Extensions And Sustain Extensibility（RFC 8701）
    // Only chrome can do
    ctx.set_grease_enabled(true);

    // Set TLS permute extensions options
    ctx.set_permute_extensions(true);

    // Set TLS curves list
    ctx.set_curves_list(join!(":", "X25519MLKEM768", "X25519", "P-256", "P-384"))?;

    // Set TLS signature algorithms list
    ctx.set_sigalgs_list(join!(
        ":",
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512"
    ))?;

    // Set TLS cipher list
    ctx.set_cipher_list(join!(
        ":",
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA"
    ))?;

    // Set Pre Shared Key (Session Cache)
    ctx.set_session_cache_mode(SslSessionCacheMode::CLIENT);
    ctx.set_new_session_callback({
        let cache = cache.clone();
        move |ssl, session| {
            if let Ok(Some(key)) = key_index().map(|idx| ssl.ex_data(idx)) {
                cache.put(key.clone(), TlsSession(session));
            }
        }
    });

    let mut ssl = Ssl::new(&ctx.build())?;

    // Set ECH grease
    // Only chrome can do
    ssl.set_enable_ech_grease(true);

    // Set ALPN: h2 preferred, then http/1.1 (Chrome order)
    ssl.set_alpn_protos(b"\x02h2\x08http/1.1")?;

    // Set ALPS
    // Not standardize, only chrome can do
    unsafe {
        let ssl_st = ssl.as_mut() as *const _ as *mut _;
        let alps = b"h2";
        let rt = boring_sys::SSL_add_application_settings(
            ssl_st,
            alps.as_ptr(),
            alps.len(),
            std::ptr::null(),
            0,
        );
        if rt <= 0 {
            return Err(ErrorStack::get().into());
        }
        boring_sys::SSL_set_alps_use_new_codepoint(ssl_st, 1);
    }

    if let Some(session) = cache.pop(url) {
        unsafe { ssl.set_session(&session.0) }?;
    }
    let idx = key_index()?;
    ssl.set_ex_data(idx, String::from(url));

    ssl.set_hostname(sni)?;

    if !skip_verify {
        // verify hostname
        let param = ssl.param_mut();
        param.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
        param.set_host(sni)?;
    }

    Ok(ssl)
}
