use home;
use rand::rngs::OsRng;
use rsa::{pem::parse, pem::Pem, PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::{convert::TryFrom, path::Path};
use std::{error::Error, fs::File};
use std::{fmt::Display, io::prelude::*};

fn main() {
    let mut settings = match read_cli_args() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };

    let private_key_path = "/home/larodar/Documents/keys/dev/privKey.pem";
    let app_settings = AppSettings {
        home: home::home_dir().unwrap(),
    };

    let result = match settings.op {
        Operation::Decrypt => {
            let new_key_path = PathBuf::from_str(private_key_path).unwrap();
            // TODO: find a better way to do this
            match settings.data {
                OpData::CryptoOp {
                    is_path,
                    target,
                    key_path: _,
                } => {
                    settings.data = OpData::CryptoOp {
                        is_path,
                        target,
                        key_path: new_key_path,
                    };
                }
                _ => unreachable!(),
            };

            decrypt(&settings)
        }
        Operation::Encrypt => {
            let new_key_path = app_settings.home.clone();
            // TODO: find a better way to do this
            match settings.data {
                OpData::CryptoOp {
                    is_path,
                    target,
                    key_path: _,
                } => {
                    // join with name to get public key path
                    // new_key_path.join(path)
                    settings.data = OpData::CryptoOp {
                        is_path,
                        target,
                        key_path: new_key_path,
                    };
                }
                _ => unreachable!(),
            };

            encrypt(&settings)
        }
        Operation::Init => init(),
        Operation::ContactAdd => add_contact(&settings, &app_settings),
        Operation::ContactRemove => remove_contact(&settings, &app_settings),
    };

    if let Err(e) = result {
        eprintln!("{}", e);
    }
}

fn add_contact(settings: &OpSettings, app: &AppSettings) -> Result<(), CryptographicError> {
    match &settings.data {
        OpData::ContactOp { name, key_path } if settings.op == Operation::ContactAdd => {
            // path to the key file
            let contact_path = app.home.join(".qryptex").join(name.as_str());

            // contact name
            if Path::exists(contact_path.as_path()) {
                return Err(CryptographicError::new(CryptographicErrorKind::ContactAdd));
            }

            let import_path = key_path.as_ref().unwrap().as_path();
            let _ = load_pub_key(import_path)?;
            // assemble file content
            let content = std::fs::read(import_path).unwrap();
            std::fs::write(contact_path, content).unwrap();
            Ok(())
        }
        _ => Err(CryptographicError::new(CryptographicErrorKind::ContactAdd)),
    }
}

fn remove_contact(settings: &OpSettings, app: &AppSettings) -> Result<(), CryptographicError> {
    match &settings.data {
        OpData::ContactOp { name, key_path: _ } if settings.op == Operation::ContactAdd => {
            // path to the key file
            let contact_path = app.home.join(".qryptex").join(name.as_str());

            // contact name
            if !Path::exists(contact_path.as_path()) {
                return Ok(());
            }

            std::fs::remove_file(contact_path).unwrap();
            Ok(())
        }
        _ => Err(CryptographicError::new(
            CryptographicErrorKind::ContactRemove,
        )),
    }
}

fn init() -> Result<(), CryptographicError> {
    let home_dir = match home::home_dir() {
        Some(path) => path,
        None => panic!("Could not get home directory."),
    };

    // create .qryptex dir to store the information
    let app_dir = home_dir.join(".qryptex");
    std::fs::create_dir(app_dir).unwrap();

    // load contacts and keys

    // create key pair
    // TODO: figure this out

    Ok(())
}

fn encrypt(settings: &OpSettings) -> Result<(), CryptographicError> {
    match &settings.data {
        OpData::CryptoOp {
            is_path,
            target,
            key_path,
        } if settings.op == Operation::Encrypt => {
            let plaintext = match is_path {
                true => std::fs::read(target)
                    .map_err(|_| CryptographicError::new(CryptographicErrorKind::Io)),
                false => hex_to_bytes(&target),
            }?;
            let pub_key = load_pub_key(&key_path)?;
            let ciphertext = encrypt_txt(&plaintext[..], &pub_key)?;

            let ciphertext_str = ciphertext
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<String>>()
                .join("");
            println!("Success! Ciphertext: {}", ciphertext_str);
            Ok(())
        }
        _ => {
            eprintln!("Invalid data for crypto operation.");
            Err(CryptographicError::new(CryptographicErrorKind::Encryption))
        }
    }
}

fn decrypt(settings: &OpSettings) -> Result<(), CryptographicError> {
    match &settings.data {
        OpData::CryptoOp {
            is_path,
            target,
            key_path,
        } if settings.op == Operation::Decrypt => {
            let ciphertext = match is_path {
                true => std::fs::read(target)
                    .map_err(|_| CryptographicError::new(CryptographicErrorKind::Io)),
                false => hex_to_bytes(&target),
            }?;

            let private_key = load_private_key(&key_path)?;
            let plaintext_raw = decrypt_ciphertext(&ciphertext, &private_key)?;
            let plaintext = match String::from_utf8(plaintext_raw) {
                Err(_) => {
                    eprintln!("Decrypted plaintext is invalid utf8.");
                    return Err(CryptographicError::new(CryptographicErrorKind::Format));
                }
                Ok(text) => text,
            };

            println!("{}", plaintext);
            Ok(())
        }
        _ => {
            eprintln!("Invalid data for crypto operation.");
            Err(CryptographicError::new(CryptographicErrorKind::Decryption))
        }
    }
}

fn encrypt_txt(plaintext: &[u8], public_key: &RSAPublicKey) -> Result<Vec<u8>, CryptographicError> {
    // prepare encryption
    let mut rng = OsRng;
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    match public_key.encrypt(&mut rng, padding, plaintext) {
        Err(_) => Err(CryptographicError::new(CryptographicErrorKind::Encryption)),
        Ok(ciph) => Ok(ciph),
    }
}

fn decrypt_ciphertext(
    ciphertext: &[u8],
    private_key: &RSAPrivateKey,
) -> Result<Vec<u8>, CryptographicError> {
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    let plaintext = match private_key.decrypt(padding, ciphertext) {
        Err(_) => Err(CryptographicError::new(CryptographicErrorKind::Encryption)),
        Ok(ciph) => Ok(ciph),
    }?;

    Ok(plaintext)
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, CryptographicError> {
    let mut hex_bytes = hex
        .as_bytes()
        .iter()
        .filter_map(|b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        })
        .fuse();
    let mut bytes = Vec::new();
    while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
        bytes.push(h << 4 | l)
    }
    Ok(bytes)
}

fn load_pub_key(path: &Path) -> Result<RSAPublicKey, CryptographicError> {
    let pub_pem = read_key_at_path(path)?;
    let pub_key = match RSAPublicKey::try_from(pub_pem) {
        Err(_) => Err(CryptographicError::new(CryptographicErrorKind::Format)),
        Ok(key) => Ok(key),
    }?;
    Ok(pub_key)
}

fn load_private_key(path: &Path) -> Result<RSAPrivateKey, CryptographicError> {
    let private_pem = read_key_at_path(path)?;
    let private_key = match RSAPrivateKey::try_from(private_pem) {
        Err(_) => Err(CryptographicError::new(CryptographicErrorKind::Format)),
        Ok(key) => Ok(key),
    }?;
    Ok(private_key)
}

//fn gen_key_pair() {
//    let key_pair_path = "/home/laroar/Documents/keys/dev/pubKey.pem";
//    let mut rng = OsRng;
//    let bits = 2048;
//    let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
//    let public_key = RSAPublicKey::from(&private_key);
//}

fn read_key_at_path(path: &Path) -> Result<Pem, CryptographicError> {
    let mut file = match File::open(Path::new(path)) {
        Err(e) => Err(CryptographicError::from(e)),
        Ok(f) => Ok(f),
    }?;

    println!("opened file");
    let mut content = vec![];
    let _ = match file.read_to_end(&mut content) {
        Err(_) => Err(CryptographicError::new(CryptographicErrorKind::Io)),
        Ok(u) => Ok(u),
    }?;

    let key =
        parse(content).map_err(|_| CryptographicError::new(CryptographicErrorKind::InvalidKey))?;
    Ok(key)
}

/// cli definition
/// qryptex [option(s)]
/// decrypt | dec
/// encrypt | enc
/// init
/// export
/// contact add
/// contact remove
fn read_cli_args() -> Result<OpSettings, CliError> {
    let mut params = std::env::args().skip(1);
    // operation
    match params.next() {
        Some(o) => match o.as_str() {
            "decrypt" | "dec" => read_crypto_command(params, Operation::Decrypt),
            "encrypt" | "enc" => read_crypto_command(params, Operation::Encrypt),
            "contact" => read_contact_command(params),
            "init" => Ok(OpSettings {
                op: Operation::Init,
                data: OpData::Empty,
            }),
            _ => Err(CliError(String::from("Must specify operation"))),
        },
        None => Err(CliError(String::from("Must specify operation."))),
    }
}

fn read_contact_command(mut args: impl Iterator<Item = String>) -> Result<OpSettings, CliError> {
    let op = match args.next() {
        Some(m) => match m.as_str() {
            "add" => Operation::ContactAdd,
            "remove" => Operation::ContactRemove,
            _ => {
                return Err(CliError(String::from("Must specify add/remove modifier")));
            }
        },
        None => {
            return Err(CliError(String::from("Must specify add/remove modifier")));
        }
    };

    let data = match op {
        Operation::ContactAdd => {
            // expect name and path to key file
            let mut name_opt = None;
            let key_opt = None;
            while let Some(s) = args.next() {
                match s.as_str() {
                    "-n" | "--name" => match args.next().as_deref() {
                        Some("-k") | None => {
                            return Err(CliError(String::from("Missing value for --name/-n.")))
                        }
                        Some(val) => name_opt = Some(String::from(val)),
                    },
                    "-k" | "--key" => match args.next().as_deref() {
                        Some("-n") | None => {
                            return Err(CliError(String::from("Missing value for --key/-k.")))
                        }
                        Some(val) => name_opt = Some(String::from(val)),
                    },
                    _ => return Err(CliError(String::from(format!("Unknown argument: {}", s)))),
                };
            }

            let name = match name_opt {
                Some(n) => n,
                None => {
                    return Err(CliError(String::from("Missing argument: --name/-n.")));
                }
            };

            if key_opt == None {
                return Err(CliError(String::from("Missing argument: --name/-n.")));
            }

            OpData::ContactOp {
                name,
                key_path: key_opt,
            }
        }
        Operation::ContactRemove => {
            // expect a name
            match args.next() {
                Some(s) => OpData::ContactOp {
                    name: s,
                    key_path: None,
                },
                None => {
                    return Err(CliError(String::from(
                        "Missing name for contact to remove.",
                    )))
                }
            }
        }
        _ => unreachable!(),
    };

    Ok(OpSettings { op, data })
}

fn read_crypto_command(
    mut args: impl Iterator<Item = String>,
    op: Operation,
) -> Result<OpSettings, CliError> {
    let data = match args.next() {
        Some(arg) => match arg.as_str() {
            "-f" => args.next().map_or(
                Err(CliError(String::from("Missing path of plaintext file."))),
                |val| {
                    Ok(OpData::CryptoOp {
                        is_path: true,
                        target: val,
                        key_path: PathBuf::new(),
                    })
                },
            ),
            _ => match args.next().as_deref() {
                None => Ok(OpData::CryptoOp {
                    is_path: false,
                    target: arg,
                    key_path: PathBuf::new(),
                }),
                Some("-f") => Ok(OpData::CryptoOp {
                    is_path: true,
                    target: arg,
                    key_path: PathBuf::new(),
                }),
                Some(s) => Err(CliError(String::from(format!("Invalid argument: {}", s)))),
            },
        },
        None => Err(CliError(String::from("Missing path of plaintext file."))),
    }?;

    Ok(OpSettings { op, data })
}

#[derive(Debug, Clone)]
struct CliError(String);

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

struct AppSettings {
    home: PathBuf,
}

struct OpSettings {
    op: Operation,
    data: OpData,
}

enum OpData {
    Empty,
    CryptoOp {
        is_path: bool,
        target: String,
        key_path: PathBuf,
    },
    ContactOp {
        name: String,
        key_path: Option<PathBuf>,
    },
}

#[derive(Debug, PartialEq)]
enum Operation {
    Decrypt,
    Encrypt,
    Init,
    ContactAdd,
    ContactRemove,
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", "", "")
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
