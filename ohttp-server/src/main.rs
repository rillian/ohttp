#![deny(warnings, clippy::pedantic)]

use bhttp::{Message, Mode};
use ohttp::{
    hpke::{Aead, Kdf, Kem},
    KeyConfig, Server as OhttpServer, SymmetricSuite,
    ServerResponse,
};
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use structopt::StructOpt;
use url::Url;
use warp::Filter;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, StructOpt)]
#[structopt(name = "ohttp-server", about = "Serve oblivious HTTP requests.")]
struct Args {
    /// The address to bind to.
    #[structopt(default_value = "127.0.0.1:9443")]
    address: SocketAddr,

    /// When creating message/bhttp, use the indefinite-length form.
    #[structopt(long, short = "n")]
    indefinite: bool,

    /// Certificate to use for serving.
    #[structopt(long, short = "c", default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/server.crt"))]
    certificate: PathBuf,

    /// Key for the certificate to use for serving.
    #[structopt(long, short = "k", default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/server.key"))]
    key: PathBuf,
}

impl Args {
    fn mode(&self) -> Mode {
        if self.indefinite {
            Mode::IndefiniteLength
        } else {
            Mode::KnownLength
        }
    }
}

fn url_from_bhttp(request: &Message) -> Res<Url> {
    let control = request.control();
    eprintln!("request: authority {:?}", control.authority());
    if let Some(host) = request.header().get(b"host") {
        let host = std::str::from_utf8(host)?;
        eprintln!("request: host {}", &host);
        // FIXME: map error
        let scheme = control.scheme().unwrap();
        let scheme = std::str::from_utf8(scheme)?;
        eprintln!("request: scheme {}", &scheme);
        let temp = format!("{}://{}", scheme, host);
        let mut url = Url::parse(&temp)?;
        if let Some(path) = control.path() {
            let path = std::str::from_utf8(path)?;
            eprintln!("request: path {}", &path);
            url.set_path(path);
        }
        return Ok(url);
    }

    Err("Couldn't read target url!".into())
}

// Construct a 'bad request' error response
fn err_response(message: &str) -> Message {
    let mut response = Message::response(400);
    response.write_content(message);
    response.write_content("\r\n");

    response
}

/// Encapsulate a bhttp message
fn enc_message(state: ServerResponse, message: Message, mode: Mode) -> Res<Vec<u8>> {
    let mut buffer = Vec::new();
    message.write_bhttp(mode, &mut buffer)?;
    let encoded = state.encapsulate(&buffer)?;

    Ok(encoded)
}

fn generate_reply(
    ohttp_ref: &Arc<Mutex<OhttpServer>>,
    enc_request: &[u8],
    mode: Mode,
) -> Res<Vec<u8>> {
    // Decrypt and parse the inner request.
    let mut ohttp = ohttp_ref.lock().unwrap();
    let (request, server_response) = ohttp.decapsulate(enc_request)?;
    let bin_request = Message::read_bhttp(&mut BufReader::new(&request[..]))?;

    // Convert to something we can send out.
    let url = url_from_bhttp(&bin_request)?;
    eprintln!("request: url {}", &url);

    // Validate against our policy.
    if url.scheme() != "https" {
        let response = err_response("request must but https");
        let encoded = enc_message(server_response, response, mode)?;
        // Received the message ok, so tell proxy success, but
        // pass an error code through to the client.
        return Ok(encoded);
    }
    if url.domain().filter(|name| name == &"p3a-json.bravesoftware.com").is_none() {
        // Maybe should be 403?
        let response = err_response("Target domain not allowed");
        let encoded = enc_message(server_response, response, mode)?;
        return Ok(encoded);
    }
    let status = format!("Request url {}\r\n", &url);

    eprintln!("Constructing request {}", &url);
    let client = ureq::AgentBuilder::new()
        .https_only(true)
        .timeout(std::time::Duration::from_secs(2))
        .build();
    let fwd = match bin_request.control().method() {
        Some(b"post") | Some(b"POST") => {
            // Forward the request body
            let content = bin_request.content();
            eprintln!("  ... post {} bytes", content.len());
            client.post(url.as_str())
                .set("Content-Type", "application/json")
                .set("X-Brave-P3A", "?1")
                .send_bytes(content)
        },
        Some(b"get") | Some(b"GET") => {
            eprintln!("  ... get");
            client.get(url.as_str()).call()
        },
        Some(method) => {
            let name = std::str::from_utf8(method)?;
            eprintln!("  ... unsupported method {}", name);
            let response = err_response("Method not allowed");
            return Ok(enc_message(server_response, response, mode)?);
        },
        None => {
            eprintln!("  ... no method supplied!");
            let response = err_response("No HTTP method supplied");
            return Ok(enc_message(server_response, response, mode)?);
        },
    };
    // FIXME: copy headers
    eprintln!("  ureq returned {:?}", fwd);
    let inner_response = fwd?;
    eprintln!("upstream: {:?}", inner_response);

    let mut bin_response = Message::response(200);
    bin_response.write_content(b"Received:\r\n---8<---\r\n");
    let mut tmp = Vec::new();
    bin_request.write_http(&mut tmp)?;
    bin_response.write_content(&tmp);
    bin_response.write_content(b"--->8---\r\n");
    bin_response.write_content(&status);

    let mut response = Vec::new();
    bin_response.write_bhttp(mode, &mut response)?;
    let enc_response = server_response.encapsulate(&response)?;
    Ok(enc_response)
}

#[allow(clippy::unused_async)]
async fn serve(
    body: warp::hyper::body::Bytes,
    ohttp: Arc<Mutex<OhttpServer>>,
    mode: Mode,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    match generate_reply(&ohttp, &body[..], mode) {
        Ok(resp) => Ok(warp::http::Response::builder()
            .header("Content-Type", "message/ohttp-res")
            .body(resp)),
        Err(e) => {
            if let Ok(oe) = e.downcast::<::ohttp::Error>() {
                Ok(warp::http::Response::builder()
                    .status(422)
                    .body(Vec::from(format!("Error: {:?}", oe).as_bytes())))
            } else {
                Ok(warp::http::Response::builder()
                    .status(400)
                    .body(Vec::from(&b"Request error"[..])))
            }
        }
    }
}

fn with_ohttp(
    ohttp: Arc<Mutex<OhttpServer>>,
) -> impl Filter<Extract = (Arc<Mutex<OhttpServer>>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || Arc::clone(&ohttp))
}

#[tokio::main]
async fn main() -> Res<()> {
    let args = Args::from_args();
    ::ohttp::init();

    let config = KeyConfig::new(
        0,
        Kem::X25519Sha256,
        vec![
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm),
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
        ],
    )?;
    let ohttp = OhttpServer::new(config)?;
    println!("Config: {}", hex::encode(ohttp.config().encode()?));
    let mode = args.mode();

    let filter = warp::post()
        .and(warp::path::end())
        .and(warp::body::bytes())
        .and(with_ohttp(Arc::new(Mutex::new(ohttp))))
        .and(warp::any().map(move || mode))
        .and_then(serve);
    warp::serve(filter)
        .tls()
        .cert_path(args.certificate)
        .key_path(args.key)
        .run(args.address)
        .await;

    Ok(())
}
