use crate::error::Result;
use std::{net::TcpListener, sync::mpsc};

fn handle_request(stream: &std::net::TcpStream) -> Option<String> {
    use std::io::BufRead;

    let buf = std::io::BufReader::new(stream);
    for line in buf.lines() {
        let line: String = line.unwrap();
        if !line.starts_with("GET") {
            continue;
        }

        let start_idx = line.find("?code=")? + "?code=".len();
        let line = &line[start_idx..];
        let end_idx = line.find(|c: char| !c.is_alphanumeric())?;

        let token = &line[..end_idx];

        return Some(token.to_string());
    }

    None
}

pub fn start_token_server(
    uri: &str,
    handler: impl FnOnce(String) -> Result<oauth2::basic::BasicTokenResponse> + Send + Sync + 'static,
) -> Result<mpsc::Receiver<Result<crate::Token>>> {
    use std::io::Write;

    let (tx, rx) = mpsc::channel();

    let listener = TcpListener::bind(uri)?;

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => match handle_request(&stream) {
                    Some(auth_code) => {
                        let token_response = handler(auth_code).map(crate::Token::from_response);
                        tx.send(token_response).unwrap();
                        let _ = write!(stream, "Success");
                        break;
                    }
                    None => {
                        let _ = write!(stream, "Error: no code found in query params");
                    }
                },
                Err(e) => eprintln!("failed to listen: {}", e),
            }
        }
    });

    Ok(rx)
}
