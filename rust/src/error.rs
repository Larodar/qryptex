use std::convert::From;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use openssl::error::ErrorStack;

#[derive(Debug)]
pub enum QryptexError {
    Cli(CliError),
    Crypto(CryptographicError),
    Contact(ContactsError),
}

impl QryptexError {
    pub fn new_cli(kind: CliErrorKind) -> QryptexError {
        QryptexError::Cli(CliError(kind))
    }

    pub fn new_crypto(kind: CryptographicErrorKind) -> QryptexError {
        QryptexError::Crypto(CryptographicError::new(kind))
    }

    pub fn new_contact(kind: ContactsErrorKind) -> QryptexError {
        QryptexError::Contact(ContactsError::new(kind))
    }
}

impl From<CliError> for QryptexError {
    fn from(v: CliError) -> Self {
        QryptexError::Cli(v)
    }
}

impl From<ContactsError> for QryptexError {
    fn from(v: ContactsError) -> Self {
        QryptexError::Contact(v)
    }
}

impl From<CryptographicError> for QryptexError {
    fn from(v: CryptographicError) -> Self {
        QryptexError::Crypto(v)
    }
}

impl Error for QryptexError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            QryptexError::Cli(inner) => inner.source(),
            QryptexError::Crypto(inner) => inner.source(),
            QryptexError::Contact(inner) => inner.source(),
        }
    }
}

impl Display for QryptexError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // call fmt of inner
        match self {
            Self::Cli(err) => err.fmt(f),
            Self::Crypto(err) => err.fmt(f),
            Self::Contact(err) => err.fmt(f),
        }
    }
}

#[derive(Debug)]
pub struct ContactsError {
    kind: ContactsErrorKind,
    inner: Option<Box<dyn Error + Send + Sync>>,
}

impl ContactsError {
    pub fn new(kind: ContactsErrorKind) -> ContactsError {
        ContactsError { kind, inner: None }
    }

    pub fn with_inner(
        kind: ContactsErrorKind,
        inner: Box<dyn Error + Send + Sync>,
    ) -> ContactsError {
        ContactsError {
            kind,
            inner: Some(inner),
        }
    }
}

impl Display for ContactsError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // TODO: build a cool error message here
        let message = match &self.inner {
            Some(e) => format!("{}", e),
            None => format!("{}", self.kind),
        };
        writeln!(f, "The contact operation failed: {}", message.as_str())
    }
}

impl Error for ContactsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ContactsErrorKind {
    NotFound,
    ExistsAlready,
    Io,
    //Unknown,
}

impl From<ContactsErrorKind> for ContactsError {
    fn from(v: ContactsErrorKind) -> Self {
        ContactsError::new(v)
    }
}

impl Display for ContactsErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            ContactsErrorKind::NotFound => "Contact not found.",
            ContactsErrorKind::ExistsAlready => "A contact with the name does already exist.",
            ContactsErrorKind::Io => "The file operation failed.",
            //ContactsErrorKind::Unknown => "Something went wrong. Cause unknown.",
        };

        write!(f, "{}", message)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CliError(CliErrorKind);

impl Display for CliError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        writeln!(
            f,
            "The command line input was invalid:", // "Invalid command"?
        )?;
        self.0.fmt(f)
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CliErrorKind {
    MissingOperation,
    MissingPlaintext,
    MissingPlaintextPath,
    MissingOutputPath,
    MissingContactName,
    MissingModifier,
    MissingNameValue,
    MissingKeyValue,
    InvalidOutputPath,
    InvalidArgument,
}

impl From<CliErrorKind> for CliError {
    fn from(v: CliErrorKind) -> Self {
        CliError(v)
    }
}

impl Display for CliErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            CliErrorKind::MissingOperation => "Please specify an operation.",
            CliErrorKind::MissingPlaintextPath => "Path to plaintext file expected but not found.",
            CliErrorKind::MissingPlaintext => "No plaintext was supplied.",
            CliErrorKind::MissingOutputPath => "Path of output file expected but not found.",
            CliErrorKind::MissingContactName => {
                "Please specify a contact by name for the operation."
            }
            CliErrorKind::MissingModifier => {
                "A modifier was expected but not found. See the help for usage information."
            }
            CliErrorKind::MissingNameValue => {
                "A name for the new contact was expected but not found."
            }
            CliErrorKind::MissingKeyValue => "A path to the key was expected but not found.",
            CliErrorKind::InvalidArgument => "Unknown argument.",
            CliErrorKind::InvalidOutputPath => "The output path must be a valid file location.",
        };
        write!(f, "{}", message)
    }
}

#[derive(Debug)]
pub struct CryptographicError {
    kind: CryptographicErrorKind,
    inner: InnerError,
}

impl CryptographicError {
    pub fn new(kind: CryptographicErrorKind) -> CryptographicError {
        CryptographicError {
            kind,
            inner: InnerError::None,
        }
    }

    pub fn with_inner(kind: CryptographicErrorKind, inner: InnerError) -> CryptographicError {
        CryptographicError { kind, inner }
    }
}

#[derive(Debug)]
pub enum InnerError {
    None,
    AesGcm(aes_gcm::Error),
    Io(std::io::Error),
    //Other(Box<dyn Error>),
}

impl AsRef<InnerError> for InnerError {
    fn as_ref(&self) -> &InnerError {
        self
    }
}

impl From<CryptographicErrorKind> for CryptographicError {
    fn from(kind: CryptographicErrorKind) -> CryptographicError {
        CryptographicError {
            kind,
            inner: InnerError::None,
        }
    }
}

impl From<std::io::Error> for CryptographicError {
    fn from(io_err: std::io::Error) -> CryptographicError {
        CryptographicError {
            kind: CryptographicErrorKind::Io,
            inner: InnerError::Io(io_err),
        }
    }
}

impl Display for CryptographicError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // TODO: build a cool error message here
        let info = match self.source() {
            Some(s) => format!("{}", s),
            None => format!("{}", self.kind),
        };
        writeln!(
            f,
            "The cryptographic operation failed:\r\n{}",
            info.as_str()
        )
    }
}

impl Error for CryptographicError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.inner {
            // InnerError::Other(e) => Some(e.as_ref()),
            InnerError::Io(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum CryptographicErrorKind {
    Io,
    InvalidKey,
    Format,
    Encryption,
    Decryption,
    KeyGen(ErrorStack),
}

impl Display for CryptographicErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            CryptographicErrorKind::Io => "IO operation failed",
            CryptographicErrorKind::InvalidKey => "The key was not in ",
            CryptographicErrorKind::Format => "The data was malformed",
            CryptographicErrorKind::Encryption => "Encrypting the data failed",
            CryptographicErrorKind::Decryption => "Decrypting the data failed",
            CryptographicErrorKind::KeyGen(errors) => {
                writeln!(f, "Key generation failed:")?;
                for e in errors.errors() {
                    writeln!(f, "{}", e)?;
                }
                return Ok(());
            }
        };
        write!(f, "{}", message)
    }
}

impl From<ErrorStack> for CryptographicErrorKind {
    fn from(v: ErrorStack) -> Self {
        CryptographicErrorKind::KeyGen(v)
    }
}
