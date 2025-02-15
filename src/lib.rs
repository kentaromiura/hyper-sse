extern crate base64;
extern crate dryoc;
extern crate futures;
extern crate hyper;

use dryoc::dryocbox::*;

extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tokio;

use futures::future;
use hyper::rt::{Future, Stream};
use hyper::{Body, Chunk, Request, Response, StatusCode};

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};
use tokio::timer::Interval;

type Clients = Vec<Client>;
type Channels<C> = HashMap<C, Clients>;

/// Push server implementing Server-Sent Events (SSE).
///
/// SSE allow pushing events to browsers over HTTP without polling.
/// This library uses async hyper to support many concurrent push
/// connections and is compatible with the Rocket framework. It
/// supports multiple parallel channels and client authentication.
///
/// The generic parameter `C` specifies the type used to distinguish
/// the different channels and can be chosen arbitrarily.
///
/// Because the Server implements `Sync`, it can e.g. be stored
/// in a static variable using `lazy_static`.
pub struct Server<C> {
    channels: Mutex<Channels<C>>,
    next_id: AtomicUsize,
    token_key: dryoc::classic::crypto_secretbox::Key,
    nonce: dryoc::classic::crypto_secretbox::Nonce,
}

#[derive(Deserialize, Serialize)]
struct AuthToken<C> {
    created: SystemTime,
    allowed_channel: Option<C>,
}

impl<C: DeserializeOwned + Eq + Hash + FromStr + Send + Serialize> Server<C> {
    /// Create a new SSE push-server.
    pub fn new() -> Server<C> {
        //libhydrogen::init().expect("could not init libhydrogen");

        Server {
            nonce: dryoc::classic::crypto_secretbox::Nonce::gen(),
            channels: Mutex::new(HashMap::new()),
            next_id: AtomicUsize::new(0),
            token_key: dryoc::classic::crypto_secretbox::crypto_secretbox_keygen(),
        }
    }

    /// Push a message for the event to all clients registered on the channel.
    ///
    /// The message is first serialized and then send to all registered
    /// clients on the given channel, if any.
    ///
    /// Returns an error if the serialization fails.
    pub fn push<S: Serialize>(
        &self,
        channel: C,
        event: &str,
        message: &S,
    ) -> Result<(), serde_json::error::Error> {
        let payload = serde_json::to_string(message)?;
        let message = format!("event: {}\ndata: {}\n\n", event, payload);

        self.send_chunk_to_channel(message, channel);

        Ok(())
    }

    /// Initiate a new SSE stream for the given request.
    ///
    /// The request must include a valid authorization token. The
    /// channel is parsed from the last segment of the uri path. If the
    /// request cannot be parsed correctly or the auth token is expired,
    /// an appropriate http error response is returned.
    pub fn create_stream(&self, request: &Request<Body>) -> Response<Body> {
        use base64::{decode_config, URL_SAFE_NO_PAD};
        use dryoc::classic::crypto_secretbox::crypto_secretbox_open_easy;
        use dryoc::constants::CRYPTO_SECRETBOX_MACBYTES;

        // Extract channel from uri path (last segment)
        let channel = request
            .uri()
            .path()
            .rsplit('/')
            .next()
            .and_then(|channel_str| C::from_str(channel_str).ok());

        // Extract auth token from query, decode, decrypt and deserialize
        let nonce = self.nonce.clone();
        let key = self.token_key.clone();

        let token = request
            .uri()
            .query()
            .and_then(|query| decode_config(query, URL_SAFE_NO_PAD).ok())
            .and_then(|opaque_token| {
                // Decrypt
                let mut decrypted = vec![0u8; opaque_token.len() - CRYPTO_SECRETBOX_MACBYTES];
                let res = crypto_secretbox_open_easy(&mut decrypted, &opaque_token, &nonce, &key);
                match res.err() {
                    Some(_) => None,
                    None => Some(decrypted),
                }
            })
            .and_then(|token_str| serde_json::from_slice::<AuthToken<C>>(&token_str).ok());

        // Check if the request contained a valid channel and token
        let (channel, token) = match (channel, token) {
            (Some(channel), Some(token)) => (channel, token),
            _ => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::empty())
                    .expect("Could not create response");
            }
        };

        // Check that the auth token is not older than 24 hours and
        // specifies the correct channel
        let correct_channel = match token.allowed_channel {
            Some(token_channel) => channel == token_channel,
            None => true, // None means all channels are allowed
        };
        let fresh_token = match SystemTime::now().duration_since(token.created) {
            Ok(duration) => duration.as_secs() < 24 * 60 * 60,
            Err(_) => true, // Token is in the future (time shift)
        };
        if !correct_channel || !fresh_token {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::empty())
                .expect("Could not create response");
        }

        let (sender, body) = Body::channel();
        self.add_client(channel, sender);

        Response::builder()
            .header("Cache-Control", "no-cache")
            .header("X-Accel-Buffering", "no")
            .header("Content-Type", "text/event-stream")
            .header("Access-Control-Allow-Origin", "*")
            .body(body)
            .expect("Could not create response")
    }

    /// Create an opaque authorization token that will be checked
    /// in `create_stream` before establishing the SSE stream.
    ///
    /// A new token can be send to the client on every request, as
    /// creating and checking the tokens is cheap. The token is valid
    /// for 24 hours after it has been generated and can only be used
    /// on the specified channel if specified. The token must be passed
    /// as the query url segment to the sse endpoint.
    ///
    /// Returns an error if the channel serialization fails.
    pub fn generate_auth_token(
        &self,
        channel: Option<C>,
    ) -> Result<String, serde_json::error::Error> {
        use base64::{encode_config, URL_SAFE_NO_PAD};

        use dryoc::classic::crypto_secretbox::crypto_secretbox_easy;
        use dryoc::constants::CRYPTO_SECRETBOX_MACBYTES;

        let token = AuthToken {
            created: SystemTime::now(),
            allowed_channel: channel,
        };
        let token = serde_json::to_vec(&token)?;
        // Encrypt
        let nonce = self.nonce.clone();
        let key = self.token_key.clone();
        let mut ciphertext = vec![0u8; token.len() + CRYPTO_SECRETBOX_MACBYTES];
        crypto_secretbox_easy(&mut ciphertext, &token, &nonce, &key).expect("encrypt failed");

        let opaque_token = encode_config(&ciphertext, URL_SAFE_NO_PAD);

        Ok(opaque_token)
    }

    /// Send hearbeat to all clients on all channels.
    ///
    /// This should be called regularly (e.g. every minute) to detect
    /// a disconnect of the underlying TCP connection.
    pub fn send_heartbeats(&self) {
        self.send_chunk_to_all_clients(":\n\n".into());
    }

    /// Remove disconnected clients.
    ///
    /// This removes all clients from all channels that have closed the
    /// connection or are not responding to the heartbeats, which caused
    /// a TCP timeout.
    ///
    /// This function should be called regularly (e.g. together with
    /// `send_heartbeats`) to keep the memory usage low.
    pub fn remove_stale_clients(&self) {
        let mut channels = self.channels.lock().unwrap();

        channels.retain(|_, clients| {
            clients.retain(|client| {
                if let Some(first_error) = client.first_error {
                    if first_error.elapsed() > Duration::from_secs(5) {
                        return false;
                    }
                }
                true
            });

            !clients.is_empty()
        });
    }

    /// Run a push SSE server on the given address.
    ///
    /// Convenience function for starting a push server on a new thread.
    /// Maintenance is done automatically, so you don't have to call
    /// `send_heartbeats` or `remove_stale_clients`.
    ///
    /// This function will panic in the current thread if it cannot
    /// listen on the specified address.
    pub fn spawn(&'static self, listen: SocketAddr) -> JoinHandle<()> {
        use hyper::service::service_fn_ok;

        let sse_handler = move |req: Request<Body>| self.create_stream(&req);

        let http_server = hyper::Server::bind(&listen)
            .serve(move || service_fn_ok(sse_handler))
            .map_err(|e| panic!("Push server failed: {}", e));

        let maintenance = Interval::new(Instant::now(), Duration::from_secs(45))
            .for_each(move |_| {
                self.remove_stale_clients();
                self.send_heartbeats();
                future::ok(())
            })
            .map_err(|e| panic!("Push maintenance failed: {}", e));

        thread::spawn(move || {
            hyper::rt::run(http_server.join(maintenance).map(|_| ()));
        })
    }

    fn add_client(&self, channel: C, sender: hyper::body::Sender) {
        self.channels
            .lock()
            .unwrap()
            .entry(channel)
            .or_insert_with(Default::default)
            .push(Client {
                tx: sender,
                id: self.next_id.fetch_add(1, Ordering::SeqCst),
                first_error: None,
            });
    }

    fn send_chunk_to_channel(&self, chunk: String, channel: C) {
        let mut channels = self.channels.lock().unwrap();

        match channels.get_mut(&channel) {
            Some(clients) => {
                for client in clients.iter_mut() {
                    let chunk = Chunk::from(chunk.clone());
                    client.send_chunk(chunk).ok();
                }
            }
            None => {} // Currently no clients on the given channel
        };
    }

    fn send_chunk_to_all_clients(&self, chunk: String) {
        let mut channels = self.channels.lock().unwrap();

        for client in channels.values_mut().flat_map(IntoIterator::into_iter) {
            let chunk = Chunk::from(chunk.clone());
            client.send_chunk(chunk).ok();
        }
    }
}

#[derive(Debug)]
struct Client {
    tx: hyper::body::Sender,
    id: usize,
    first_error: Option<Instant>,
}

impl Client {
    fn send_chunk(&mut self, chunk: Chunk) -> Result<(), Chunk> {
        let result = self.tx.send_data(chunk);

        match (&result, self.first_error) {
            (Err(_), None) => {
                // Store time when an error was first seen
                self.first_error = Some(Instant::now());
            }
            (Ok(_), Some(_)) => {
                // Clear error when write succeeds
                self.first_error = None;
            }
            _ => {}
        }

        result
    }
}
