use std::convert::{From, Into};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub enum QryptexError {
    Cli(CliError),
    Crypto(CryptographicError),
    Contact(ContactsError),
}

impl QryptexError {
    pub fn new_cli(err: CliError) -> QryptexError {
        QryptexError::Cli(err)
    }

    pub fn new_crypto(err: CryptographicError) -> QryptexError {
        QryptexError::Crypto(err)
    }

    pub fn new_contact(err: ContactsError) -> QryptexError {
        QryptexError::Contact(err)
    }
}

impl Error for QryptexError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        // TODO: impl some source? Or return inner?
        None
    }
}

impl Display for QryptexError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "An error occured:\n{}",
            match self {
                Self::Cli(err) => err.into(),
                Self::Crypto(err) => err.into(),
                Self::Contact(err) => err.into(),
            }
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct ContactsError(ContactsErrorKind);

impl Into<&'static str> for ContactsError {
    fn into(self) -> &'static str {
        self.0.into()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ContactsErrorKind {
    NotFound,
    ExistsAlready,
}

impl Into<ContactsError> for ContactsErrorKind {
    fn into(self) -> ContactsError {
        ContactsError(self)
    }
}

impl Into<&'static str> for ContactsErrorKind {
    fn into(self) -> &'static str {
        match self {
            NotFound => "Contact not found.",
            ExistsAlready => "A contact with the name does already exist.",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CliError(CliErrorKind);

impl Into<&'static str> for CliError {
    fn into(self) -> &'static str {
        self.0.into()
    }
}

impl CliError {
    pub fn new(kind: CliErrorKind) -> CliError {
        CliError(kind)
    }
}
#[derive(Debug, Clone, Copy)]
pub enum CliErrorKind {
    MissingOperation,
    MissingPlaintextPath,
    MissingOutputPath,
    MissingContactName,
    MissingModifier,
    MissingNameValue,
    MissingKeyValue,
    InvalidArgument,
}

impl Into<CliError> for CliErrorKind {
    fn into(self) -> CliError {
        CliError(self)
    }
}

impl Into<&'static str> for CliErrorKind {
    fn into(self) -> &'static str {
        match self {
            MissingOperation => "Please specify an operation.",
            MissingPlaintextPath => "Path to plaintext file expected but not found.",
            MissingOutputPath => "Path of output file expected but not found.",
            MissingContactName => "Please specify a contact by name for the operation.",
            MissingModifier => {
                "A modifier was expected but not found. See the help for usage information."
            }
            MissingNameValue => "A name for the new contact was expected but not found.",
            MissingKeyValue => "A path to the key was expected but not found.",
            InvalidArgument => "Unknown argument.",
        }
    }
}

#[derive(Debug)]
pub struct CryptographicError {
    kind: CryptographicErrorKind,
    inner: Option<Box<dyn Error + Send + Sync>>,
}

impl Into<&'static str> for CryptographicError {
    fn into(self) -> &'static str {
        self.kind.into()
    }
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
        // TODO: build a cool error message here
        write!(f, "An error occured: ")
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

impl Into<&'static str> for CryptographicErrorKind {
    fn into(self) -> &'static str {
        match self {
            Self::Io => "IO operation failed",
            Self::InvalidKey => "The key was not in ",
            Self::Format => "The data was malformed",
            Self::Encryption => "Encrypting the data failed",
            Self::Decryption => "Decrypting the data failed",
            Self::ContactAdd => "Adding the contact failed",
            Self::ContactRemove => "Removing the contact failed",
        }
    }
}
