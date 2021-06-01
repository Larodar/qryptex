use std::convert::{From, Into};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

#[derive(Debug, Clone)]
pub struct CliError(String);

impl CliError {
    pub fn new(message: String) -> CliError {
        CliError(message)
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl Display for CliError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", <&CliError as Into<String>>::into(self))
    }
}

impl Into<String> for &CliError {
    fn into(self) -> String {
        self.0.clone()
    }
}

impl Into<String> for CliError {
    fn into(self) -> String {
        self.0
    }
}

impl From<String> for CliError {
    fn from(s: String) -> Self {
        CliError(s)
    }
}

impl From<&String> for CliError {
    fn from(s: &String) -> Self {
        CliError(s.clone())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CryptographicErrorKind {
    Io,
    InvalidKey,
    Format,
    Encryption,
    Decryption,
    ContactAdd,
    ContactRemove,
}

impl CryptographicErrorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            &CryptographicErrorKind::Io => "IO operation failed",
            &CryptographicErrorKind::InvalidKey => "The key was not in ",
            &CryptographicErrorKind::Format => "The data was malformed",
            &CryptographicErrorKind::Encryption => "Encrypting the data failed",
            &CryptographicErrorKind::Decryption => "Decrypting the data failed",
            &CryptographicErrorKind::ContactAdd => "Adding the contact failed",
            &CryptographicErrorKind::ContactRemove => "Removing the contact failed",
        }
    }
}

#[derive(Debug)]
pub struct CryptographicError {
    kind: CryptographicErrorKind,
    inner: Option<Box<dyn Error + Send + Sync>>,
}

impl CryptographicError {
    pub fn new(kind: CryptographicErrorKind) -> CryptographicError {
        CryptographicError { kind, inner: None }
    }
}

impl From<CryptographicErrorKind> for CryptographicError {
    fn from(kind: CryptographicErrorKind) -> CryptographicError {
        CryptographicError { kind, inner: None }
    }
}

impl From<std::io::Error> for CryptographicError {
    fn from(io_err: std::io::Error) -> CryptographicError {
        CryptographicError {
            kind: CryptographicErrorKind::Io,
            inner: Some(Box::new(io_err)),
        }
    }
}

impl Display for CryptographicError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "An error occured: {}", self.kind.as_str())
    }
}

impl Error for CryptographicError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self.inner.as_ref() {
            Some(e) => Some(e.as_ref()),
            None => None,
        }
    }
}
