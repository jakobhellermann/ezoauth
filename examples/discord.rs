use ezoauth::OAuthConfig;

const AUTH_URL: &'static str = "https://discord.com/api/oauth2/authorize";
const TOKEN_URL: &'static str = "https://discord.com/api/oauth2/token";

fn main() -> Result<(), ezoauth::Error> {
    let client_id = "";
    let client_secret = "";
    let redirect_url = "http://localhost:8000";
    let listen_on = "localhost:8000";

    let config = OAuthConfig {
        auth_url: AUTH_URL.to_string(),
        token_url: TOKEN_URL.to_string(),
        redirect_url: redirect_url.to_string(),
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
    };
    let (rx, auth_url) = ezoauth::authenticate(config, listen_on)?;

    println!("Browse to: {}\n", auth_url);

    let token = rx.recv().unwrap()?;

    println!("Token: {}", token.access_token());

    Ok(())
}
