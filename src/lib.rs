#![warn(missing_docs)]
//! An easy to use OAuth2 client flow library based on [oauth2-rs](https://docs.rs/oauth2/).
//! ```rust,no_run
//! # fn main() -> Result<(), ezoauth::Error> {
//! let config = ezoauth::OAuthConfig {
//!     auth_url: "https://discord.com/api/oauth2/authorize".into(),
//!     token_url: "https://discord.com/api/oauth2/token".into(),
//!     redirect_url: "http://localhost:8000",
//!     client_id: "...".into(),
//!     client_secret: "...".into(),
//!     scopes: vec!["identify".into()],
//! };
//! let (rx, auth_url) = ezoauth::authenticate(config, "localhost:8000".to_string())?;
//!
//! println!("Browse to {}", auth_url);
//!
//! let token = rx.recv().unwrap()?;
//! # Ok(())
//! # }
//! ```

mod error;
mod server;

pub use error::Error;
use error::Result;

use std::sync::mpsc;

use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenResponse, TokenUrl,
};

/// A token response, which contains the access and refresh token as well as metadata like scopes, expiry info and the token type
pub struct Token(BasicTokenResponse);
impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("access_token", &format_args!("[redacted]"))
            .field("token_type", &self.token_type())
            .field("expires_in", &self.expires_in())
            .field("refresh_token", &self.refresh_token())
            .field("scopes", &self.scopes())
            .finish()
    }
}

#[allow(missing_docs)]
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

/// Used to specify how you want to perform your OAuth authentication.
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub struct OAuthConfig {
    pub auth_url: String,
    pub token_url: String,
    pub redirect_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
}

/// The `authenticate` function performs the OAuth2 flow.
///
/// It starts a webserver in a background thread which listens on the `listen_on` parameter and should be accessible from the `config`'s [`redirect_url`](OAuthConfig#structfield.redirect_url).
/// # Example
/// ```rust,no_run
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
///     scopes: vec!["identify".into()],
/// };
/// let (rx, auth_url) = ezoauth::authenticate(config, listen_on)?;
///
/// println!("Browse to {}", auth_url);
///
/// let token = rx.recv().unwrap()?;
///
/// println!("Token: {:?}", token);
/// # Ok(())
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

    let mut auth_request = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge);
    for scope in config.scopes {
        auth_request = auth_request.add_scope(Scope::new(scope));
    }

    // Generate the full authorization URL.
    let (auth_url, _csrf_token) = auth_request.url();

    let token_receiver = server::start_token_server(listen_on, move |auth_code| {
        let token_result = client
            .exchange_code(AuthorizationCode::new(auth_code))
            .set_pkce_verifier(pkce_verifier)
            .request(oauth2::reqwest::http_client)?;

        Ok(token_result)
    })?;

    Ok((token_receiver, auth_url.to_string()))
}
