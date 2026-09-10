//! A recording RFC 7662 introspection endpoint.
//!
//! Answers with a canned status and body, and keeps what it received so tests
//! can assert on the request itself — that the `Authorization` header is sent
//! verbatim, that the token travels as a form field, and how many times the
//! endpoint was actually called (which is how caching is observed).

use std::sync::{Arc, Mutex};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[derive(Clone, Debug)]
pub struct Recorded {
    pub authorization: Option<String>,
    pub content_type: Option<String>,
    pub body: String,
}

pub struct MockIntrospection {
    pub url: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
    _task: tokio::task::JoinHandle<()>,
}

impl MockIntrospection {
    /// Serves `body` with HTTP `status` for every request.
    pub async fn start(status: u16, body: impl Into<String>) -> Self {
        let body = body.into();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/introspect", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorder = requests.clone();

        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let Some(request) = read_request(&mut socket).await else {
                    continue;
                };
                recorder.lock().unwrap().push(parse(&request));

                let reason = if (200..300).contains(&status) {
                    "OK"
                } else {
                    "ERROR"
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });

        Self {
            url,
            requests,
            _task: task,
        }
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }

    pub fn call_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

/// Reads headers, then exactly `Content-Length` bytes of body.
async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<String> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 1024];

    loop {
        let read = socket.read(&mut chunk).await.ok()?;
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..read]);

        let text = String::from_utf8_lossy(&raw);
        let Some(headers_end) = text.find("\r\n\r\n") else {
            continue;
        };
        let expected: usize = text[..headers_end]
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().ok())?
            })
            .unwrap_or(0);

        if raw.len() >= headers_end + 4 + expected {
            break;
        }
    }

    Some(String::from_utf8_lossy(&raw).into_owned())
}

fn parse(request: &str) -> Recorded {
    let header = |name: &str| {
        request.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    };
    let body = request
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_default()
        .to_string();

    Recorded {
        authorization: header("authorization"),
        content_type: header("content-type"),
        body,
    }
}
