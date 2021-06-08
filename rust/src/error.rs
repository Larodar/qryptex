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

impl Into<&'static str> for ContactsError {
    fn into(self) -> &'static str {
        self.0.into()
    }
}

impl Into<&'static str> for &ContactsError {
    fn into(self) -> &'static str {
        self.0.into()
    }
}

impl Display for ContactsError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // TODO: build a cool error message here
        write!(f, "The contact operation failed: \n")
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

impl Into<ContactsError> for ContactsErrorKind {
    fn into(self) -> ContactsError {
        ContactsError(self)
    }
}

impl Into<&'static str> for ContactsErrorKind {
    fn into(self) -> &'static str {
        match self {
            Self::NotFound => "Contact not found.",
            Self::ExistsAlready => "A contact with the name does already exist.",
            Self::Io => "The file operation failed. Second instance running?",
            Self::Unknown => "Something went wrong. Cause unknown.",
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

impl Into<&'static str> for &CliError {
    fn into(self) -> &'static str {
        self.0.into()
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
            Self::MissingOperation => "Please specify an operation.",
            Self::MissingPlaintextPath => "Path to plaintext file expected but not found.",
            Self::MissingOutputPath => "Path of output file expected but not found.",
            Self::MissingContactName => "Please specify a contact by name for the operation.",
            Self::MissingModifier => {
                "A modifier was expected but not found. See the help for usage information."
            }
            Self::MissingNameValue => "A name for the new contact was expected but not found.",
            Self::MissingKeyValue => "A path to the key was expected but not found.",
            Self::InvalidArgument => "Unknown argument.",
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

impl Into<&'static str> for &CryptographicError {
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
