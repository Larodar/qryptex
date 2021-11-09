use std::path::PathBuf;

pub fn build_app_settings(dbg: bool) -> AppSettings {
    let user_home = home::home_dir().unwrap();
    let app_home = match dbg {
        true => user_home.join(".qryptex_dev"),
        false => user_home.join(".qryptex"),
    };

    let contacts_dir = app_home.join("contacts");
    let contacts = match load_contact_names(contacts_dir.as_path()) {
        Ok(c) => c,
        Err(_) => vec![],
    };
    let local_keys_path = app_home.join("_self");
    AppSettings {
        home: app_home,
        contacts_dir,
        local_keys_path,
        contacts,
        debug: false,
    }
}

#[derive(Debug)]
pub struct AppSettings {
    pub home: PathBuf,
    pub contacts_dir: PathBuf,
    pub local_keys_path: PathBuf,
    pub contacts: Vec<String>,
    pub debug: bool,
}

/// Contains configuration information for a cryptographic operation.
#[derive(Debug, Clone, PartialEq)]
pub struct CryptoOp {
    /// Shows whether or not the provided string is a path to a file, which is to be encrypted
    /// Contains either the plaintext for the crypto operation or a path to a file, depending on
    /// the value of the is_path flag.
    target: CryptoTarget,
    /// The name of the contact, who receives the message.
    contact: String,
    /// A path to which the ciphertext will be written.
    output_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CryptoTarget {
    File(PathBuf),
    Text(String),
}

impl CryptoTarget {
    pub fn new_file(path: PathBuf) -> CryptoTarget {
        CryptoTarget::File(path)
    }

    pub fn new_text(s: String) -> CryptoTarget {
        CryptoTarget::Text(s)
    }
}

impl From<PathBuf> for CryptoTarget {
    fn from(v: PathBuf) -> Self {
        CryptoTarget::new_file(v)
    }
}

impl From<String> for CryptoTarget {
    fn from(v: String) -> Self {
        CryptoTarget::new_text(v)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContactOp {
    name: String,
    key_path: Option<PathBuf>,
}

#[derive(Debug, PartialEq)]
pub enum Operation {
    Decrypt(Option<CryptoOp>),
    Encrypt(Option<CryptoOp>),
    Init,
    ContactAdd(Option<ContactOp>),
    ContactRemove(Option<ContactOp>),
    ContactList,
}

impl Operation {
    pub fn with_crypto_data(self, data: CryptoOp) -> Operation {
        match self {
            Operation::Decrypt(_) => Operation::Decrypt(Some(data)),
            Operation::Encrypt(_) => Operation::Encrypt(Some(data)),
            _ => panic!("Cannot add crypto command data to non-crypto operation."),
        }
    }

    pub fn with_contact_data(self, data: ContactOp) -> Operation {
        match self {
            Operation::ContactAdd(_) => Operation::ContactAdd(Some(data)),
            Operation::ContactRemove(_) => Operation::ContactRemove(Some(data)),
            _ => panic!("Cannot add contact command data to non-contact operation."),
        }
    }
}
