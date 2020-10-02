use ezoauth::OAuthConfig;

const AUTH_URL: &'static str = "https://discord.com/api/oauth2/authorize";
const TOKEN_URL: &'static str = "https://discord.com/api/oauth2/token";

fn main() -> Result<(), ezoauth::Error> {
    let client_id = "";
    let client_secret = "";
    let redirect_url = "http://localhost:8000";
    let listen_on = "localhost:8000";

    let config = OAuthConfig {
        auth_url: AUTH_URL,
        token_url: TOKEN_URL,
        redirect_url,
        client_id,
        client_secret,
        scopes: vec!["identify"],
    };
    let (rx, auth_url) = ezoauth::authenticate(config, listen_on)?;

    println!("Browse to: {}\n", auth_url);

    let token = rx.recv().unwrap()?;

    println!("Token: {:?}", token);

    Ok(())
}
