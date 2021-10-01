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
    pub fn new_cli(kind: CliErrorKind) -> QryptexError {
        QryptexError::Cli(CliError(kind))
    }

    pub fn new_crypto(kind: CryptographicErrorKind) -> QryptexError {
        QryptexError::Crypto(CryptographicError::new(kind))
    }

    pub fn new_contact(kind: ContactsErrorKind) -> QryptexError {
        QryptexError::Contact(ContactsError(kind))
    }

    pub fn as_message(&self) -> &'static str {
        match self {
            Self::Cli(err) => err.into(),
            Self::Crypto(err) => err.into(),
            Self::Contact(err) => err.into(),
        }
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
        writeln!(f, "An error occured!",)?;
        // call fmt of inner
        write!(f, "{}", self.as_message())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ContactsError(ContactsErrorKind);

impl From<ContactsError> for &'static str {
    fn from(v: ContactsError) -> Self {
        v.0.into()
    }
}

impl From<&ContactsError> for &'static str {
    fn from(v: &ContactsError) -> Self {
        v.into()
    }
}

impl Display for ContactsError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // TODO: build a cool error message here
        writeln!(f, "The contact operation failed: ")
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
    Unknown,
}

impl From<ContactsErrorKind> for ContactsError {
    fn from(v: ContactsErrorKind) -> Self {
        ContactsError(v)
    }
}

impl From<ContactsErrorKind> for &'static str {
    fn from(c: ContactsErrorKind) -> Self {
        match c {
            ContactsErrorKind::NotFound => "Contact not found.",
            ContactsErrorKind::ExistsAlready => "A contact with the name does already exist.",
            ContactsErrorKind::Io => "The file operation failed. Second instance running?",
            ContactsErrorKind::Unknown => "Something went wrong. Cause unknown.",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CliError(CliErrorKind);

impl From<CliError> for &'static str {
    fn from(v: CliError) -> Self {
        v.0.into()
    }
}

impl From<&CliError> for &'static str {
    fn from(v: &CliError) -> Self {
        v.into()
    }
}

impl CliError {
    pub fn new(kind: CliErrorKind) -> CliError {
        CliError(kind)
    }
}
impl Display for CliError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // TODO: build a cool error message here
        write!(
            f,
            "The command line input was invalid: " // "Invalid command"?
        )
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

impl From<CliErrorKind> for &'static str {
    fn from(v: CliErrorKind) -> Self {
        match v {
            CliErrorKind::MissingOperation => "Please specify an operation.",
            CliErrorKind::MissingPlaintextPath => "Path to plaintext file expected but not found.",
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
        }
    }
}

#[derive(Debug)]
pub struct CryptographicError {
    kind: CryptographicErrorKind,
    inner: Option<Box<dyn Error + Send + Sync>>,
}

impl From<CryptographicError> for &'static str {
    fn from(v: CryptographicError) -> Self {
        v.kind.into()
    }
}

impl From<&CryptographicError> for &'static str {
    fn from(v: &CryptographicError) -> Self {
        v.kind.into()
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
        write!(
            f,
            "An error occured when attempting a cryptographic operation: "
        )
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

impl From<CryptographicErrorKind> for &'static str {
    fn from(v: CryptographicErrorKind) -> &'static str {
        match v {
            CryptographicErrorKind::Io => "IO operation failed",
            CryptographicErrorKind::InvalidKey => "The key was not in ",
            CryptographicErrorKind::Format => "The data was malformed",
            CryptographicErrorKind::Encryption => "Encrypting the data failed",
            CryptographicErrorKind::Decryption => "Decrypting the data failed",
            CryptographicErrorKind::ContactAdd => "Adding the contact failed",
            CryptographicErrorKind::ContactRemove => "Removing the contact failed",
        }
    }
}
