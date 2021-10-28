use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;

use contacts::*;
use error::{CliErrorKind, ContactsErrorKind, CryptographicErrorKind, QryptexError};
use rand::prelude::StdRng;
use rand::{RngCore, SeedableRng};
use rsa::{pem::parse, pem::Pem, PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::{convert::TryFrom, path::Path};

mod contacts;
mod error;

/// The encrypted data has the following format:
/// Nonce|Key|Ciphertext
/// 12bytes|32bytes|...
/// These first 44 bytes are RSA encrypted.
fn main() {
    let mut op_settings = match read_cli_args() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };

    let mut app_settings = build_app_settings(&op_settings);

    run_command(&mut op_settings, &mut app_settings);
}

fn build_app_settings(op_settings: &OpSettings) -> AppSettings {
    let user_home = home::home_dir().unwrap();
    let app_home = user_home.join(".qryptex");
    let contacts_dir = app_home.join("contacts");
    let local_keys_path = app_home.join("_self");
    AppSettings {
        home: app_home,
        contacts_dir: contacts_dir.clone(),
        local_keys_path,
        // TODO: match on op to assign empty vec directly on init?
        contacts: match op_settings.op {
            Operation::Init => vec![],
            _ => load_contact_names(contacts_dir.as_path()).unwrap(),
        },
    }
}

fn run_command(op_settings: &mut OpSettings, app_settings: &mut AppSettings) {
    let result = match op_settings.op {
        Operation::Decrypt => {
            // TODO: find a better way to do this
            match &op_settings.data {
                OpData::CryptoOp {
                    is_path,
                    target,
                    contact: _,
                    output_path: _,
                } => {
                    op_settings.data = OpData::CryptoOp {
                        is_path: *is_path,
                        target: target.clone(),
                        contact: String::new(),
                        output_path: None,
                    };
                }
                _ => unreachable!(),
            };

            decrypt(&op_settings, &app_settings)
        }
        Operation::Encrypt => encrypt(&op_settings, &app_settings),
        Operation::Init => {
            init(&app_settings).map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Io))
        }
        Operation::ContactAdd => add_contact(&op_settings, &app_settings),
        Operation::ContactRemove => remove_contact(&op_settings, &app_settings),
        Operation::ContactList => {
            let _ = app_settings
                .contacts
                .iter()
                .map(|c| println!("{}", c))
                .collect::<()>();
            Ok(())
        }
    };

    handle_result(result);
}

fn handle_result(result: Result<(), QryptexError>) {
    if let Err(e) = result {
        println!("The operation resulted in an error: {}", e);
    } else {
        println!("The operation finished successfully.");
    }
}

fn add_contact(settings: &OpSettings, app: &AppSettings) -> Result<(), QryptexError> {
    match &settings.data {
        OpData::ContactOp {
            name,
            key_path: Some(path),
        } if settings.op == Operation::ContactAdd => try_add_contact(app, name, path.as_path()),
        _ => Err(QryptexError::new_contact(ContactsErrorKind::Unknown)),
    }
}

fn try_add_contact(app: &AppSettings, name: &String, key_path: &Path) -> Result<(), QryptexError> {
    if app.contacts.contains(name) {
        return Err(QryptexError::new_contact(ContactsErrorKind::ExistsAlready));
    }

    // path to the key file
    let contact_path = app.contacts_dir.join(name);

    // contact name
    if Path::exists(contact_path.as_path()) {
        // TODO: handle this better, the dir may be corrupted?
        return Err(QryptexError::new_contact(ContactsErrorKind::ExistsAlready));
    }

    let bytes = fs::read(key_path).map_err(|_| QryptexError::new_contact(ContactsErrorKind::Io))?;
    let _ = pub_key_from_bytes(&bytes)?;
    // assemble file content
    fs::write(contact_path, &bytes).unwrap();
    Ok(())
}

fn remove_contact(settings: &OpSettings, app: &AppSettings) -> Result<(), QryptexError> {
    match &settings.data {
        OpData::ContactOp { name, .. } if settings.op == Operation::ContactRemove => {
            // path to the key file
            contacts::delete_contact_file(app.contacts_dir.as_path(), name)
                .map_err(|_| QryptexError::new_contact(ContactsErrorKind::Io))
        }
        _ => Err(QryptexError::new_contact(ContactsErrorKind::Unknown)),
    }
}

fn init(settings: &AppSettings) -> std::io::Result<()> {
    // create .qryptex dir to store the information
    println!("Creating app home at ~/.qryptex");
    fs::create_dir(settings.home.as_path())?;
    // create contacts dir to store the contact files
    println!("Creating contact directory at ~/.qryptex/contacts");
    init_contacts_dir(settings.contacts_dir.as_path())?;

    println!("Creating local key pair at ~/.qryptex/_self");
    fs::create_dir(settings.local_keys_path.as_path())?;

    println!("Initialization complete.");

    // create key pair
    // TODO: figure this out

    Ok(())
}

fn encrypt(settings: &OpSettings, app: &AppSettings) -> Result<(), QryptexError> {
    match &settings.data {
        OpData::CryptoOp {
            is_path,
            target,
            contact,
            output_path,
        } if settings.op == Operation::Encrypt => {
            let plaintext = match is_path {
                true => std::fs::read(target)
                    .map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Io)),
                false => Ok(target.bytes().collect()),
            }?;
            let pub_key = load_contact(contact, app)?;
            // build session key
            let (nonce, key) = generate_operation_primitives();
            // build aes cipher
            let mut cipher = Aes256Gcm::new_from_slice(&key).unwrap();
            let ciphertext = encrypt_plaintext(&plaintext[..], &mut cipher, &nonce)?;
            let mut prefix = [0u8; 44];
            prefix[..12].copy_from_slice(&nonce);
            prefix[12..].copy_from_slice(&key);
            let encrypted_prefix = encrypt_primitives(&prefix, &pub_key)?;
            if *is_path {
                // output must be a file
                let ciphertext_path = match output_path {
                    Some(p) => Ok(p.clone()),
                    None => PathBuf::from_str(target.as_str())
                        .map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Format)),
                }?;
                std::fs::write(ciphertext_path, ciphertext)
                    .map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Io))
            } else {
                // output is a small string which can and should be written to stdout
                let ciphertext_str = encrypted_prefix
                    .iter()
                    .chain(ciphertext.iter())
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<String>>()
                    .join("");
                println!("Success!\nCiphertext: {}", ciphertext_str);
                Ok(())
            }
        }
        _ => Err(QryptexError::new_crypto(CryptographicErrorKind::Encryption)),
    }
}

fn decrypt(settings: &OpSettings, app: &AppSettings) -> Result<(), QryptexError> {
    match &settings.data {
        OpData::CryptoOp {
            is_path,
            target,
            contact: _,
            output_path,
        } if settings.op == Operation::Decrypt => {
            let prefixed_ciphertext = match is_path {
                true => std::fs::read(target)
                    .map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Io)),
                false => hex_to_bytes(target),
            }?;

            let (encrypted_prefix, ciphertext) =
                (&prefixed_ciphertext[..44], &prefixed_ciphertext[44..]);
            let path = app.local_keys_path.join("private.pem");
            let private_key = load_private_key(path.as_path())?;
            let (nonce, key) = recover_primitives(encrypted_prefix, &private_key)?;

            let mut cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
            let plaintext_raw = decrypt_ciphertext(ciphertext, &mut cipher, &nonce)?;
            if *is_path {
                // output must be a file
                let plaintext_path = match output_path {
                    Some(p) => Ok(p.clone()),
                    None => {
                        // TODO: process the path
                        PathBuf::from_str(target.as_str())
                            .map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Format))
                    }
                }?;
                std::fs::write(plaintext_path, plaintext_raw)
                    .map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Io))
            } else {
                // output is a small string which should be written to stdout
                let plaintext = String::from_utf8(plaintext_raw)
                    .map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Format))?;
                println!("Success!\n{}", plaintext);
                Ok(())
            }
        }
        _ => {
            eprintln!("Invalid data for crypto operation.");
            Err(QryptexError::new_crypto(CryptographicErrorKind::Decryption))
        }
    }
}

fn recover_primitives(
    prefix: &[u8],
    private_key: &RSAPrivateKey,
) -> Result<([u8; 12], [u8; 32]), QryptexError> {
    if prefix.len() != 44 {
        return Err(QryptexError::new_crypto(CryptographicErrorKind::Format));
    }

    let mut nonce = [0u8; 12];
    let mut key = [0u8; 32];

    let decrypted_prefix = decrypt_primitives(prefix, private_key)?;
    nonce.copy_from_slice(&decrypted_prefix[..12]);
    key.copy_from_slice(&decrypted_prefix[12..]);

    Ok((nonce, key))
}

/// Generates a aes key to use for an encryption operation.
fn generate_operation_primitives() -> ([u8; 12], [u8; 32]) {
    let mut nonce = [0u8; 12];
    let mut key = [0u8; 32];
    let mut rng = StdRng::from_entropy();
    rng.fill_bytes(&mut nonce);
    rng.fill_bytes(&mut key);

    (nonce, key)
}

/// Encrypts the aes key with the contacts public key.
fn encrypt_primitives(key: &[u8], public_key: &RSAPublicKey) -> Result<Vec<u8>, QryptexError> {
    let mut rng = StdRng::from_entropy();
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    match public_key.encrypt(&mut rng, padding, key) {
        Err(_) => Err(QryptexError::new_crypto(CryptographicErrorKind::Encryption)),
        Ok(ciph) => Ok(ciph),
    }
}

/// Decrypts the prefix, which holds the nonce and the AES-Key
fn decrypt_primitives(key: &[u8], private_key: &RSAPrivateKey) -> Result<Vec<u8>, QryptexError> {
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    let decrypted_key = match private_key.decrypt(padding, key) {
        Err(_) => Err(QryptexError::new_crypto(CryptographicErrorKind::Decryption)),
        Ok(plain) => Ok(plain),
    }?;

    Ok(decrypted_key)
}

/// TODO: Make this streaming.
fn encrypt_plaintext(
    plaintext: &[u8],
    cipher: &mut Aes256Gcm,
    nonce: &[u8; 12],
) -> Result<Vec<u8>, QryptexError> {
    let ciphertext = cipher
        .encrypt(GenericArray::from_slice(nonce), plaintext)
        .expect("encryption failed");
    Ok(ciphertext)
}

/// TODO: Make this streaming.
fn decrypt_ciphertext(
    ciphertext: &[u8],
    cipher: &mut Aes256Gcm,
    nonce: &[u8; 12],
) -> Result<Vec<u8>, QryptexError> {
    let plaintext = cipher
        .decrypt(GenericArray::from_slice(nonce), ciphertext)
        .expect("decryption failed");
    Ok(plaintext)
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, QryptexError> {
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

fn load_contact(contact_name: &str, app: &AppSettings) -> Result<RSAPublicKey, QryptexError> {
    let bytes = contacts::load_contact_key_bytes(app.contacts_dir.as_path(), contact_name)
        .map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Io))?;
    let pub_key = pub_key_from_bytes(&bytes)?;
    Ok(pub_key)
}

fn pub_key_from_bytes(bytes: &[u8]) -> Result<RSAPublicKey, QryptexError> {
    let pub_pem =
        parse(bytes).map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::InvalidKey))?;
    let pub_key = match RSAPublicKey::try_from(pub_pem) {
        Err(_) => Err(QryptexError::new_crypto(CryptographicErrorKind::Format)),
        Ok(key) => Ok(key),
    }?;

    Ok(pub_key)
}

fn load_private_key(path: &Path) -> Result<RSAPrivateKey, QryptexError> {
    let private_pem = read_key_at_path(path)?;
    let private_key = match RSAPrivateKey::try_from(private_pem) {
        Err(_) => Err(QryptexError::new_crypto(CryptographicErrorKind::Format)),
        Ok(key) => Ok(key),
    }?;
    Ok(private_key)
}

fn read_key_at_path(path: &Path) -> Result<Pem, QryptexError> {
    let bytes = fs::read(path).map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Io))?;
    let pem =
        parse(bytes).map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::InvalidKey))?;
    Ok(pem)
}

/// cli definition
/// qryptex [option(s)]
/// decrypt | dec
/// encrypt | enc
/// init
/// export
/// contact add
/// contact remove
fn read_cli_args() -> Result<OpSettings, QryptexError> {
    let mut params = std::env::args().skip(1);
    match params.next() {
        // operation
        Some(o) => match o.as_str() {
            "decrypt" | "dec" => read_crypto_command(params, Operation::Decrypt),
            "encrypt" | "enc" => read_crypto_command(params, Operation::Encrypt),
            "contact" => read_contact_command(params),
            "init" => Ok(OpSettings {
                op: Operation::Init,
                data: OpData::Empty,
            }),
            _ => Err(QryptexError::new_cli(CliErrorKind::MissingOperation)),
        },
        None => Err(QryptexError::new_cli(CliErrorKind::MissingOperation)),
    }
}

fn read_contact_command(
    mut args: impl Iterator<Item = String>,
) -> Result<OpSettings, QryptexError> {
    let op = match args.next() {
        Some(m) => match m.as_str() {
            "add" => Operation::ContactAdd,
            "del" | "delete" => Operation::ContactRemove,
            "ls" | "list" => Operation::ContactList,
            _ => return Err(QryptexError::new_cli(CliErrorKind::MissingModifier)),
        },
        None => return Err(QryptexError::new_cli(CliErrorKind::MissingModifier)),
    };

    let data = match op {
        Operation::ContactAdd => {
            // expect name and path to key file
            let mut name_opt = None;
            let mut key_opt = None;
            while let Some(s) = args.next() {
                match s.as_str() {
                    "-n" | "--name" => match args.next().as_deref() {
                        Some("-k") | None => {
                            return Err(QryptexError::new_cli(CliErrorKind::MissingNameValue))
                        }
                        Some(val) => name_opt = Some(String::from(val)),
                    },
                    "-k" | "--key" => match args.next().as_deref() {
                        Some("-n") | None => {
                            return Err(QryptexError::new_cli(CliErrorKind::MissingKeyValue))
                        }
                        Some(val) => {
                            key_opt = Some(PathBuf::from_str(val).map_err(|_| {
                                QryptexError::new_cli(CliErrorKind::InvalidArgument)
                            })?)
                        }
                    },
                    _ => return Err(QryptexError::new_cli(CliErrorKind::InvalidArgument)),
                };
            }

            let name = match name_opt {
                Some(n) => n,
                None => {
                    return Err(QryptexError::new_cli(CliErrorKind::MissingNameValue));
                }
            };

            if key_opt == None {
                return Err(QryptexError::new_cli(CliErrorKind::MissingKeyValue));
            }

            OpData::ContactOp {
                name,
                key_path: key_opt,
            }
        }
        Operation::ContactRemove => {
            // expect a name
            match args.next().as_deref() {
                Some("-n") => match args.next() {
                    Some(val) => OpData::ContactOp {
                        name: val,
                        key_path: None,
                    },
                    None => return Err(QryptexError::new_cli(CliErrorKind::MissingNameValue)),
                },
                Some(s) => OpData::ContactOp {
                    name: String::from_str(s).unwrap(),
                    key_path: None,
                },
                None => return Err(QryptexError::new_cli(CliErrorKind::MissingContactName)),
            }
        }
        Operation::ContactList => OpData::Empty,
        _ => unreachable!(),
    };

    Ok(OpSettings { op, data })
}

fn read_crypto_command(
    mut args: impl Iterator<Item = String>,
    op: Operation,
) -> Result<OpSettings, QryptexError> {
    let mut is_path = false;
    let mut target = String::new();
    let mut contact = String::new();
    let mut output_path = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-f" | "--file" => args.next().map_or(
                Err(QryptexError::new_cli(CliErrorKind::MissingPlaintextPath)),
                |val| {
                    target = val;
                    Ok(())
                },
            ),
            "-o" | "--output" => args.next().map_or(
                Err(QryptexError::new_cli(CliErrorKind::MissingOutputPath)),
                |val| {
                    let path = match PathBuf::from_str(val.as_str()) {
                        Ok(p) => match p.is_file() {
                            true => Ok(p),
                            false => Err(QryptexError::new_cli(CliErrorKind::InvalidOutputPath)),
                        },
                        Err(_) => Err(QryptexError::new_cli(CliErrorKind::InvalidOutputPath)),
                    }?;
                    output_path = Some(path);
                    Ok(())
                },
            ),
            "-c" | "--contact" => args.next().map_or(
                Err(QryptexError::new_cli(CliErrorKind::MissingContactName)),
                |val| {
                    contact.push_str(val.as_str());
                    Ok(())
                },
            ),
            _ => match args.next().as_deref() {
                None => {
                    target.push_str(arg.as_str());
                    is_path = false;
                    Ok(())
                }
                Some("-f") => {
                    target.push_str(arg.as_str());
                    is_path = true;
                    Ok(())
                }
                // TODO: communicate the invalid argument
                Some(_) => Err(QryptexError::new_cli(CliErrorKind::InvalidArgument)),
            },
        }?;
    }

    Ok(OpSettings {
        op,
        data: OpData::CryptoOp {
            is_path,
            target,
            contact,
            output_path,
        },
    })
}

#[derive(Debug)]
struct AppSettings {
    home: PathBuf,
    contacts_dir: PathBuf,
    local_keys_path: PathBuf,
    contacts: Vec<String>,
}

#[derive(Debug)]
struct OpSettings {
    op: Operation,
    data: OpData,
}

#[derive(Debug)]
enum OpData {
    Empty,
    CryptoOp {
        is_path: bool,
        target: String,
        contact: String,
        output_path: Option<PathBuf>,
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
    ContactList,
}
