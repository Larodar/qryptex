use contacts::*;
use error::{CliError, CryptographicError, CryptographicErrorKind};
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
                        output_path: PathBuf::new(),
                    };
                }
                _ => unreachable!(),
            };

            decrypt(&op_settings, &app_settings)
        }
        Operation::Encrypt => encrypt(&op_settings, &app_settings),
        Operation::Init => {
            init(&app_settings).map_err(|_| CryptographicError::new(CryptographicErrorKind::Io))
        }
        Operation::ContactAdd => add_contact(&op_settings, &app_settings),
        Operation::ContactRemove => remove_contact(&op_settings, &app_settings),
    };

    if let Err(e) = result {
        eprintln!("{}", e);
    }
}

fn add_contact(settings: &OpSettings, app: &AppSettings) -> Result<(), CryptographicError> {
    match &settings.data {
        OpData::ContactOp { name, key_path } if settings.op == Operation::ContactAdd => {
            if !app.contacts.contains(name) {
                return Err(CryptographicError::new(CryptographicErrorKind::ContactAdd));
            }

            // path to the key file
            let contact_path = app.home.join(".qryptex").join(name.as_str());

            // contact name
            if Path::exists(contact_path.as_path()) {
                return Err(CryptographicError::new(CryptographicErrorKind::ContactAdd));
            }

            let import_path = key_path.as_ref().unwrap().as_path();
            let bytes = fs::read(import_path)
                .map_err(|_| CryptographicError::new(CryptographicErrorKind::Io))?;
            let _ = pub_key_from_bytes(&bytes)?;
            // assemble file content
            fs::write(contact_path, &bytes).unwrap();
            Ok(())
        }
        _ => Err(CryptographicError::new(CryptographicErrorKind::ContactAdd)),
    }
}

fn remove_contact(settings: &OpSettings, app: &AppSettings) -> Result<(), CryptographicError> {
    match &settings.data {
        OpData::ContactOp { name, key_path: _ } if settings.op == Operation::ContactAdd => {
            // path to the key file
            contacts::delete_contact_file(app.contacts_dir.as_path(), name)
                .map_err(|_| CryptographicError::new(CryptographicErrorKind::Io))
        }
        _ => Err(CryptographicError::new(
            CryptographicErrorKind::ContactRemove,
        )),
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

fn encrypt(settings: &OpSettings, app: &AppSettings) -> Result<(), CryptographicError> {
    match &settings.data {
        OpData::CryptoOp {
            is_path,
            target,
            contact,
            output_path: _,
        } if settings.op == Operation::Encrypt => {
            let plaintext = match is_path {
                true => std::fs::read(target)
                    .map_err(|_| CryptographicError::new(CryptographicErrorKind::Io)),
                false => hex_to_bytes(&target),
            }?;
            let pub_key = load_contact(contact, app)?;
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

fn decrypt(settings: &OpSettings, app: &AppSettings) -> Result<(), CryptographicError> {
    match &settings.data {
        OpData::CryptoOp {
            is_path,
            target,
            contact: _,
            output_path: _,
        } if settings.op == Operation::Decrypt => {
            let ciphertext = match is_path {
                true => std::fs::read(target)
                    .map_err(|_| CryptographicError::new(CryptographicErrorKind::Io)),
                false => hex_to_bytes(&target),
            }?;

            let private_key = load_private_key(app.home.join("private.pem").as_path())?;
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

fn load_contact(
    contact_name: &String,
    app: &AppSettings,
) -> Result<RSAPublicKey, CryptographicError> {
    let bytes = contacts::load_contact_key_bytes(app.contacts_dir.as_path(), contact_name)
        .map_err(|_| CryptographicError::new(CryptographicErrorKind::Io))?;
    let pub_key = pub_key_from_bytes(&bytes)?;
    Ok(pub_key)
}

fn pub_key_from_bytes(bytes: &Vec<u8>) -> Result<RSAPublicKey, CryptographicError> {
    let pub_pem =
        parse(bytes).map_err(|_| CryptographicError::new(CryptographicErrorKind::InvalidKey))?;
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

fn read_key_at_path(path: &Path) -> Result<Pem, CryptographicError> {
    let bytes = fs::read(path).map_err(|_| CryptographicError::new(CryptographicErrorKind::Io))?;
    let pem =
        parse(bytes).map_err(|_| CryptographicError::new(CryptographicErrorKind::InvalidKey))?;
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
            _ => Err(CliError::new(String::from("Must specify operation"))),
        },
        None => Err(CliError::new(String::from("Must specify operation."))),
    }
}

fn read_contact_command(mut args: impl Iterator<Item = String>) -> Result<OpSettings, CliError> {
    let op = match args.next() {
        Some(m) => match m.as_str() {
            "add" => Operation::ContactAdd,
            "remove" => Operation::ContactRemove,
            _ => {
                return Err(CliError::new(String::from(
                    "Must specify add/remove modifier",
                )));
            }
        },
        None => {
            return Err(CliError::new(String::from(
                "Must specify add/remove modifier",
            )));
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
                            return Err(CliError::new(String::from("Missing value for --name/-n.")))
                        }
                        Some(val) => name_opt = Some(String::from(val)),
                    },
                    "-k" | "--key" => match args.next().as_deref() {
                        Some("-n") | None => {
                            return Err(CliError::new(String::from("Missing value for --key/-k.")))
                        }
                        Some(val) => name_opt = Some(String::from(val)),
                    },
                    _ => {
                        return Err(CliError::new(String::from(format!(
                            "Unknown argument: {}",
                            s
                        ))))
                    }
                };
            }

            let name = match name_opt {
                Some(n) => n,
                None => {
                    return Err(CliError::new(String::from("Missing argument: --name/-n.")));
                }
            };

            if key_opt == None {
                return Err(CliError::new(String::from("Missing argument: --name/-n.")));
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
                    return Err(CliError::new(String::from(
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
    let mut is_path = false;
    let mut target = String::new();
    let mut contact = String::new();
    let mut output_path = PathBuf::new();
    match args.next() {
        Some(arg) => match arg.as_str() {
            "-f" | "--file" => args.next().map_or(
                Err(CliError::new(String::from(
                    "Missing path of plaintext file.",
                ))),
                |val| {
                    target = val;
                    Ok(())
                },
            ),
            "-o" | "--output" => args.next().map_or(
                Err(CliError::new(String::from("Missing path of output file."))),
                |val| {
                    output_path.push(val.as_str());
                    Ok(())
                },
            ),
            "-c" | "--contact" => args.next().map_or(
                Err(CliError::new(String::from("Missing contact name."))),
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
                Some(s) => Err(CliError::new(String::from(format!(
                    "Invalid argument: {}",
                    s
                )))),
            },
        },
        None => Err(CliError::new(String::from(
            "Missing path of plaintext file.",
        ))),
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
        output_path: PathBuf,
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
