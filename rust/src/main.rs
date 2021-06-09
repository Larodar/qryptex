use contacts::*;
use error::{CliErrorKind, ContactsErrorKind, CryptographicErrorKind, QryptexError};
use home;
use rand::rngs::OsRng;
use rsa::{pem::parse, pem::Pem, PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::{convert::TryFrom, path::Path};

mod contacts;
mod error;

fn main() {
    let mut op_settings = match read_cli_args() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };

    let private_key_path = "/home/larodar/Documents/keys/dev/privKey.pem";
    let home_dir = home::home_dir().unwrap();
    let home = home_dir.join(".qryptex").clone();
    let contacts_dir = home_dir.join("contacts");
    let app_settings = AppSettings {
        home,
        contacts_dir: contacts_dir.clone(),
        contacts: load_contact_names(contacts_dir.as_path()).unwrap(),
    };

    let result = match op_settings.op {
        Operation::Decrypt => {
            let new_key_path = String::from_str(private_key_path).unwrap();
            // TODO: find a better way to do this
            match op_settings.data {
                OpData::CryptoOp {
                    is_path,
                    target,
                    contact: _,
                    output_path: _,
                } => {
                    op_settings.data = OpData::CryptoOp {
                        is_path,
                        target,
                        contact: new_key_path,
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
    };

    if let Err(e) = result {
        eprintln!("{}", e);
    }
}

fn add_contact(settings: &OpSettings, app: &AppSettings) -> Result<(), QryptexError> {
    match &settings.data {
        OpData::ContactOp { name, key_path } if settings.op == Operation::ContactAdd => {
            if app.contacts.contains(name) {
                return Err(QryptexError::new_contact(ContactsErrorKind::ExistsAlready));
            }

            // path to the key file
            let contact_path = app.home.join(".qryptex").join(name.as_str());

            // contact name
            if Path::exists(contact_path.as_path()) {
                // TODO: handle this better, the dir may be corrupted?
                return Err(QryptexError::new_contact(ContactsErrorKind::ExistsAlready));
            }

            let import_path = key_path.as_ref().unwrap().as_path();
            let bytes = fs::read(import_path)
                .map_err(|_| QryptexError::new_contact(ContactsErrorKind::Io))?;
            let _ = pub_key_from_bytes(&bytes)?;
            // assemble file content
            fs::write(contact_path, &bytes).unwrap();
            Ok(())
        }
        _ => Err(QryptexError::new_contact(ContactsErrorKind::Unknown)),
    }
}

fn remove_contact(settings: &OpSettings, app: &AppSettings) -> Result<(), QryptexError> {
    match &settings.data {
        OpData::ContactOp { name, key_path: _ } if settings.op == Operation::ContactAdd => {
            // path to the key file
            contacts::delete_contact_file(app.contacts_dir.as_path(), name)
                .map_err(|_| QryptexError::new_contact(ContactsErrorKind::Io))
        }
        _ => Err(QryptexError::new_contact(ContactsErrorKind::Unknown)),
    }
}

fn init(settings: &AppSettings) -> std::io::Result<()> {
    // create .qryptex dir to store the information
    fs::create_dir(settings.home.as_path())?;
    // create contacts dir to store the contact files
    init_contacts_dir(settings.contacts_dir.as_path())?;

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
                false => hex_to_bytes(&target),
            }?;
            let pub_key = load_contact(contact, app)?;
            let ciphertext = encrypt_txt(&plaintext[..], &pub_key)?;
            if *is_path {
                // output must be a file
                let ciphertext_path = match output_path {
                    Some(p) => Ok(p.clone()),
                    None => {
                        let mut temp = match PathBuf::from_str(target.as_str()) {
                            Ok(t) => Ok(t),
                            Err(_) => Err(QryptexError::new_crypto(CryptographicErrorKind::Format)),
                        }?;
                        let _res = temp.set_extension("qrx");
                        Ok(temp)
                    }
                }?;
                std::fs::write(ciphertext_path, ciphertext)
                    .map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Io))?;
            } else {
                // output is a small string which should be written to stdout
                let ciphertext_str = ciphertext
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<String>>()
                    .join("");
                println!("Success! Ciphertext: {}", ciphertext_str);
            }

            Ok(())
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
            let ciphertext = match is_path {
                true => std::fs::read(target)
                    .map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Io)),
                false => hex_to_bytes(&target),
            }?;

            let private_key = load_private_key(app.home.join("private.pem").as_path())?;
            let plaintext_raw = decrypt_ciphertext(&ciphertext, &private_key)?;
            if *is_path {
                // output must be a file
                let plaintext_path = match output_path {
                    Some(p) => Ok(p.clone()),
                    None => {
                        let temp = match PathBuf::from_str(target.as_str()) {
                            Ok(t) => Ok(t),
                            Err(_) => Err(QryptexError::new_crypto(CryptographicErrorKind::Format)),
                        }?;
                        // TODO: process the path
                        Ok(temp)
                    }
                }?;
                std::fs::write(plaintext_path, plaintext_raw)
                    .map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Io))?;
            } else {
                // output is a small string which should be written to stdout
                let plaintext = match String::from_utf8(plaintext_raw) {
                    Err(_) => {
                        eprintln!("Decrypted plaintext is invalid utf8.");
                        return Err(QryptexError::new_crypto(CryptographicErrorKind::Format));
                    }
                    Ok(text) => text,
                };
                println!("{}", plaintext);
            }

            Ok(())
        }
        _ => {
            eprintln!("Invalid data for crypto operation.");
            Err(QryptexError::new_crypto(CryptographicErrorKind::Decryption))
        }
    }
}

fn encrypt_txt(plaintext: &[u8], public_key: &RSAPublicKey) -> Result<Vec<u8>, QryptexError> {
    // prepare encryption
    let mut rng = OsRng;
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    match public_key.encrypt(&mut rng, padding, plaintext) {
        Err(_) => Err(QryptexError::new_crypto(CryptographicErrorKind::Encryption)),
        Ok(ciph) => Ok(ciph),
    }
}

fn decrypt_ciphertext(
    ciphertext: &[u8],
    private_key: &RSAPrivateKey,
) -> Result<Vec<u8>, QryptexError> {
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    let plaintext = match private_key.decrypt(padding, ciphertext) {
        Err(_) => Err(QryptexError::new_crypto(CryptographicErrorKind::Encryption)),
        Ok(ciph) => Ok(ciph),
    }?;

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

fn load_contact(contact_name: &String, app: &AppSettings) -> Result<RSAPublicKey, QryptexError> {
    let bytes = contacts::load_contact_key_bytes(app.contacts_dir.as_path(), contact_name)
        .map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Io))?;
    let pub_key = pub_key_from_bytes(&bytes)?;
    Ok(pub_key)
}

fn pub_key_from_bytes(bytes: &Vec<u8>) -> Result<RSAPublicKey, QryptexError> {
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
            "remove" => Operation::ContactRemove,
            _ => return Err(QryptexError::new_cli(CliErrorKind::MissingModifier)),
        },
        None => return Err(QryptexError::new_cli(CliErrorKind::MissingModifier)),
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
                            return Err(QryptexError::new_cli(CliErrorKind::MissingNameValue))
                        }
                        Some(val) => name_opt = Some(String::from(val)),
                    },
                    "-k" | "--key" => match args.next().as_deref() {
                        Some("-n") | None => {
                            return Err(QryptexError::new_cli(CliErrorKind::MissingKeyValue))
                        }
                        Some(val) => name_opt = Some(String::from(val)),
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
                return Err(QryptexError::new_cli(CliErrorKind::MissingNameValue));
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
                None => return Err(QryptexError::new_cli(CliErrorKind::MissingContactName)),
            }
        }
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
    match args.next() {
        Some(arg) => match arg.as_str() {
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
        },
        None => Err(QryptexError::new_cli(CliErrorKind::MissingPlaintextPath)),
    }?;

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

struct AppSettings {
    home: PathBuf,
    contacts_dir: PathBuf,
    contacts: Vec<String>,
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
}
