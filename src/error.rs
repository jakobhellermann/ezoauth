type RequestTokenError =
    oauth2::basic::BasicRequestTokenError<oauth2::reqwest::Error<reqwest::Error>>;

/// The `ezoauth` error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// an given URL was malformatted
    #[error("invalid url given")]
    InvalidUrl,
    /// Network error when requesting a token
    #[error("{0}")]
    RequestTokenError(#[from] RequestTokenError),
    /// Failed to start the webserver
    #[error("an IO error occured while starting the webserver: {0}")]
    IO(#[from] std::io::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
