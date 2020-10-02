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

pub type Result<T, E = Error> = std::result::Result<T, E>;
