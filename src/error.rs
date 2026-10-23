use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Errors are safe to classify, but their sources must never be sent to remote clients.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid configuration or input")]
    Invalid,
    #[error("unauthorized")]
    Unauthorized,
    #[error("revision or idempotency conflict")]
    Conflict,
    #[error("not found")]
    NotFound,
    #[error("unsupported operation")]
    Unsupported,
    #[error("quota or resource limit exceeded")]
    Limit,
    #[error("transfer or JSON working-set budget exceeded")]
    TooLarge,
    #[error("integrity verification failed")]
    Integrity,
    #[error("another writer owns this metadata directory")]
    WriterActive,
    #[error("required backend guarantees unavailable")]
    Backend,
    #[error("operation timed out")]
    Timeout,
    #[error("I/O failure")]
    Io(#[from] std::io::Error),
    #[error("database failure")]
    Database(#[from] rusqlite::Error),
    #[error("blocking task failed")]
    Task(#[from] tokio::task::JoinError),
    #[error("serialization failure")]
    Json(#[from] serde_json::Error),
}

impl From<rustix::io::Errno> for Error {
    fn from(value: rustix::io::Errno) -> Self {
        Self::Io(value.into())
    }
}
