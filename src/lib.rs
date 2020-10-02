use std::{net::TcpListener, sync::mpsc};

use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::TokenResponse;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenUrl,
};

type RequestTokenError =
    oauth2::basic::BasicRequestTokenError<oauth2::reqwest::Error<reqwest::Error>>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid url given")]
    InvalidUrl,
    #[error("{0}")]
    RequestTokenError(#[from] RequestTokenError),
    #[error("an IO error occured: {0}")]
    IO(#[from] std::io::Error),
}

type Result<T, E = Error> = std::result::Result<T, E>;

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

fn start_token_server(
    uri: &str,
    handler: impl FnOnce(String) -> Result<BasicTokenResponse> + Send + Sync + 'static,
) -> Result<mpsc::Receiver<Result<Token, Error>>> {
    use std::io::Write;

    let (tx, rx) = mpsc::channel();

    let listener = TcpListener::bind(uri)?;

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => match handle_request(&stream) {
                    Some(auth_code) => {
                        let token_response = handler(auth_code).map(Token::from_response);
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

pub use oauth2::basic::BasicTokenType;
pub struct Token(BasicTokenResponse);

impl Token {
    fn from_response(token_response: BasicTokenResponse) -> Self {
        Token(token_response)
    }

    pub fn access_token(&self) -> &str {
        self.0.access_token().secret()
    }

    pub fn token_type(&self) -> &oauth2::basic::BasicTokenType {
        self.0.token_type()
    }

    pub fn expires_in(&self) -> Option<std::time::Duration> {
        self.0.expires_in()
    }

    pub fn refresh_token(&self) -> Option<&oauth2::RefreshToken> {
        self.0.refresh_token()
    }

    pub fn scopes(&self) -> Option<&Vec<Scope>> {
        self.0.scopes()
    }
}

pub struct OAuthConfig {
    pub auth_url: String,
    pub token_url: String,
    pub redirect_url: String,
    pub client_id: String,
    pub client_secret: String,
}

/// ```rust,no_run
/// use ezoauth::OAuthConfig;
///
/// const AUTH_URL: &'static str = "https://discord.com/api/oauth2/authorize";
/// const TOKEN_URL: &'static str = "https://discord.com/api/oauth2/token";
///
/// # fn main() -> Result<(), ezoauth::Error> {
/// let client_id = "<redacted>";
/// let client_secret = "<redacted>";
/// let redirect_url = "http://localhost:8000";
/// let listen_on = "localhost:8000";
///
/// let config = ezoauth::OAuthConfig {
///     auth_url: AUTH_URL.to_string(),
///     token_url: TOKEN_URL.to_string(),
///     redirect_url: redirect_url.to_string(),
///     client_id: client_id.to_string(),
///     client_secret: client_secret.to_string(),
/// };
/// let (rx, auth_url) = ezoauth::authenticate(config, listen_on)?;
///
/// println!("Browse to: {}\n", auth_url);
///
/// let token = rx.recv().unwrap()?;
///
/// println!("Token: {:?}", token);
///
/// Ok(())
/// # }
/// ```
pub fn authenticate(
    config: OAuthConfig,
    listen_on: &str,
) -> Result<(mpsc::Receiver<Result<Token>>, String)> {
    let client = BasicClient::new(
        ClientId::new(config.client_id),
        Some(ClientSecret::new(config.client_secret)),
        AuthUrl::new(config.auth_url).map_err(|_| Error::InvalidUrl)?,
        Some(TokenUrl::new(config.token_url).map_err(|_| Error::InvalidUrl)?),
    )
    .set_redirect_url(RedirectUrl::new(config.redirect_url).map_err(|_| Error::InvalidUrl)?);

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("guilds".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let token_receiver = start_token_server(listen_on, move |auth_code| {
        let token_result = client
            .exchange_code(AuthorizationCode::new(auth_code))
            .set_pkce_verifier(pkce_verifier)
            .request(oauth2::reqwest::http_client)?;

        Ok(token_result)
    })?;

    Ok((token_receiver, auth_url.to_string()))
}
