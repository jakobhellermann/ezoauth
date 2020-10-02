# ezoauth

> An easy to use OAuth2 client for rust

The crate automatically starts a webserver in a background thread and makes the authorization flow a simple matter of calling `ezoauth::authenticate` with your `OAuthConfig`.

## Example Usage

```rust
let config = ezoauth::OAuthConfig {
    auth_url: "https://discord.com/api/oauth2/authorize",
    token_url: "https://discord.com/api/oauth2/token",
    redirect_url: "http://localhost:8000",
    client_id: "...",
    client_secret: "...",
    scopes: vec!["identify"],
};
let (rx, auth_url) = ezoauth::authenticate(config, "localhost:8000")?;

println!("Browse to {}", auth_url);

let token = rx.recv().unwrap()?;
```

<br>

#### LICENSE

MIT © [Jakob Hellermann](mailto:jakob.hellermann@protonmail.com)
