use home;
use rand::rngs::OsRng;
use rsa::{pem::parse, pem::Pem, PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};
use std::fmt;
use std::{convert::TryFrom, path::Path};
use std::{error::Error, fs::File};
use std::{fmt::Display, io::prelude::*};

fn main() {
    let settings = match read_cli_args() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };

    match settings.op {
        Operation::Decrypt => decrypt(&settings),
        Operation::Encrypt => encrypt(&settings),
        Operation::Init => init(),
        Operation::ContactAdd => {}
        Operation::ContactRemove => {}
    }
}

fn init() {
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
}

fn decrypt(settings: &Settings) -> Result<(), CryptographicError> {
    let pub_key = load_pub_key()?;
    let opData = settings.data;

    let ciphertext = encrypt_txt(settings.as_str(), &pub_key)?;

    let ciphertext_str = ciphertext
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join("");
    println!("Success! Ciphertext: {}", ciphertext_str);
}

fn encrypt(settings: &Settings) -> Result<(), CryptographicError> {
    let private_key = match load_private_key() {
        Err(_) => {
            eprintln!("Could not load private key.");
            // print error
            return;
        }
        Ok(key) => key,
    };

    match settings.data {
        OpData::CryptoOp { is_path, target } if settings.op == Operation::Encrypt => Ok(()),
        _ => Err(CryptographicError("Invalid data for crypto operation.")),
    }

    let dec_plaintext = match decrypt_ciphertext(settings.target.as_str(), &private_key) {
        Err(_) => {
            eprintln!("Could not decrypt the ciphertext.");
            // print error
            return;
        }
        Ok(data) => data,
    };

    let dec_plaintext_str = match String::from_utf8(dec_plaintext) {
        Err(e) => {
            eprintln!("Decrypted plaintext is invalid utf8.");
            return;
        }
        Ok(text) => text,
    };

    println!("Decrypted: {}", dec_plaintext_str);
}

fn encrypt_txt(
    plaintext_str: &str,
    public_key: &RSAPublicKey,
) -> Result<Vec<u8>, CryptographicError> {
    // prepare data
    let plaintext_raw = plaintext_str.bytes().collect::<Vec<u8>>();

    // prepare encryption
    let mut rng = OsRng;
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    let ciphertext = match public_key.encrypt(&mut rng, padding, &plaintext_raw[..]) {
        Err(e) => Err(CryptographicError::new(CryptographicErrorKind::Encryption)),
        Ok(ciph) => Ok(ciph),
    }?;
    Ok(ciphertext)
}

fn decrypt_ciphertext(
    ciphertext_hex: &str,
    private_key: &RSAPrivateKey,
) -> Result<Vec<u8>, CryptographicError> {
    if ciphertext_hex.len() & 1 > 0 {
        // invalid hex string
        return Err(CryptographicError::new(CryptographicErrorKind::Format));
    }

    let ciphertext_raw = hex_to_bytes(ciphertext_hex)?;
    // load key

    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    let plaintext = match private_key.decrypt(padding, &ciphertext_raw[..]) {
        Err(e) => Err(CryptographicError::new(CryptographicErrorKind::Encryption)),
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

fn load_pub_key() -> Result<RSAPublicKey, CryptographicError> {
    let pub_key_path = "/home/larodar/Documents/keys/dev/pubKey.pem";
    let pub_pem = read_key_at_path(pub_key_path)?;
    let pub_key = match RSAPublicKey::try_from(pub_pem) {
        Err(_) => Err(CryptographicError::new(CryptographicErrorKind::Format)),
        Ok(key) => Ok(key),
    }?;
    Ok(pub_key)
}

fn load_private_key() -> Result<RSAPrivateKey, CryptographicError> {
    let private_key_path = "/home/larodar/Documents/keys/dev/privKey.pem";
    let private_pem = read_key_at_path(private_key_path)?;
    let private_key = match RSAPrivateKey::try_from(private_pem) {
        Err(_) => Err(CryptographicError::new(CryptographicErrorKind::Format)),
        Ok(key) => Ok(key),
    }?;
    Ok(private_key)
}

fn gen_key_pair() {
    let key_pair_path = "/home/laroar/Documents/keys/dev/pubKey.pem";
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RSAPublicKey::from(&private_key);
}

//fn write_to_path(path: &str, data: &[u8]) -> io::Result<()> {
//    let mut file = File::open(Path::new(path))?;
//    file.write_all(data)?;
//}

fn read_key_at_path(path: &str) -> Result<Pem, CryptographicError> {
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
fn read_cli_args() -> Result<Settings, CliError> {
    let mut params = std::env::args().skip(1);
    // operation
    match params.next() {
        Some(o) => match o.as_str() {
            "decrypt" | "dec" => read_crypto_command(params, Operation::Decrypt),
            "encrypt" | "enc" => read_crypto_command(params, Operation::Encrypt),
            "contact" => read_contact_command(params),
            _ => Err(CliError(String::from("Must specify operation"))),
        },
        None => Err(CliError(String::from("Must specify operation."))),
    }
}

fn read_contact_command(mut args: impl Iterator<Item = String>) -> Result<Settings, CliError> {
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
            let name_opt = None;
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

            OpData::ContactOp { name, key: key_opt }
        }
        Operation::ContactRemove => {
            // expect a name
            match args.next() {
                Some(s) => OpData::ContactOp { name: s, key: None },
                None => {
                    return Err(CliError(String::from(
                        "Missing name for contact to remove.",
                    )))
                }
            }
        }
        _ => unreachable!(),
    };

    Ok(Settings { op, data })
}

fn read_crypto_command(
    mut args: impl Iterator<Item = String>,
    op: Operation,
) -> Result<Settings, CliError> {
    let data = match args.next() {
        Some(arg) => match arg.as_str() {
            "-f" => args.next().map_or(
                Err(CliError(String::from("Missing path of plaintext file."))),
                |val| {
                    Ok(OpData::CryptoOp {
                        is_path: true,
                        target: val,
                    })
                },
            ),
            _ => match args.next().as_deref() {
                None => Ok(OpData::CryptoOp {
                    is_path: false,
                    target: arg,
                }),
                Some("-f") => Ok(OpData::CryptoOp {
                    is_path: true,
                    target: arg,
                }),
                Some(s) => Err(CliError(String::from(format!("Invalid argument: {}", s)))),
            },
        },
        None => Err(CliError(String::from("Missing path of plaintext file."))),
    }?;

    Ok(Settings { op, data })
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

struct Settings {
    op: Operation,
    data: OpData,
}

enum OpData {
    Empty,
    CryptoOp { is_path: bool, target: String },
    ContactOp { name: String, key: Option<String> },
}

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
}

impl CryptographicErrorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            &CryptographicErrorKind::Io => "IO operation failed",
            &CryptographicErrorKind::InvalidKey => "The key was not in ",
            &CryptographicErrorKind::Format => "The data was malformed",
            &CryptographicErrorKind::Encryption => "Encrypting the data failed",
            &CryptographicErrorKind::Decryption => "Decrypting the data failed",
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
