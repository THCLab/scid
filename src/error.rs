use base64::DecodeError;
use keri::error::Error as KeriError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    AppError(String),
    #[error(transparent)]
    KeriError(#[from] KeriError),
    #[error(transparent)]
    Base64Error(#[from] DecodeError),
}
