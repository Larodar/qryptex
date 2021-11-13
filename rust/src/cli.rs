//! Cli args parser module:
//! Parse the cli input and create a consistent representation of it.
//! If the input is invalid a descriptive error should be returned.
use crate::error::CliErrorKind;
use crate::error::QryptexError;
use crate::types::ContactOp;
use crate::types::CryptoOp;
use crate::types::CryptoTarget;
use crate::types::ExportOp;
use crate::types::Operation;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

/// cli definition
/// qryptex [option(s)]
/// decrypt | dec
/// encrypt | enc
/// init
/// export
/// contact add
/// contact remove
pub fn read_cli_args() -> Result<(Operation, bool), QryptexError> {
    let mut params = std::env::args().skip(1).peekable();
    let op = match &params.next() {
        // operation
        Some(o) => match o.as_str() {
            "decrypt" | "dec" => read_crypto_command(&mut params, Operation::Decrypt(None)),
            "encrypt" | "enc" => read_crypto_command(&mut params, Operation::Encrypt(None)),
            "contact" => read_contact_command(&mut params),
            "init" => Ok(Operation::Init),
            "export" => read_export_command(&mut params),
            _ => Err(QryptexError::new_cli(CliErrorKind::MissingOperation)),
        },
        None => Err(QryptexError::new_cli(CliErrorKind::MissingOperation)),
    }?;

    Ok((op, std::env::args().last() == Some("--debug".to_string())))
}

fn read_export_command(args: &mut impl Iterator<Item = String>) -> Result<Operation, QryptexError> {
    let mut out = None;
    let mut contact = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-t" | "--target" => {
                if let Some(o) = args.next() {
                    out = Some(PathBuf::from(o));
                } else {
                    return Err(QryptexError::new_cli(CliErrorKind::InvalidArgument));
                }
            }
            _ => {
                contact = Some(arg);
            }
        }
    }

    if out.is_none() {
        return Err(QryptexError::new_cli(CliErrorKind::MissingOutputPath));
    }

    let op = ExportOp {
        contact,
        output_path: out.unwrap(),
    };
    Ok(Operation::Export(op))
}

/// Forms a valid contact operation from the arguments or returns an error.
/// The error will be of type QryptexError::Cli.
/// The operation will be either Operation::ContactAdd or
/// Operation::ContactRemove.
fn read_contact_command(
    args: &mut impl Iterator<Item = String>,
) -> Result<Operation, QryptexError> {
    let op = match args.next() {
        Some(m) => match m.as_str() {
            "add" => Operation::ContactAdd(None),
            "del" | "delete" | "rem" | "remove" => Operation::ContactRemove(None),
            "ls" | "list" => Operation::ContactList,
            _ => return Err(QryptexError::new_cli(CliErrorKind::MissingModifier)),
        },
        None => return Err(QryptexError::new_cli(CliErrorKind::MissingModifier)),
    };

    match op {
        Operation::ContactAdd(_) => {
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
                            let key_path = PathBuf::from_str(val).map_err(|_| {
                                QryptexError::new_cli(CliErrorKind::InvalidArgument)
                            })?;
                            key_opt = Some(key_path);
                        }
                    },
                    "--debug" => {}
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

            Ok(op.with_contact_data(ContactOp {
                name,
                key_path: key_opt,
            }))
        }
        Operation::ContactRemove(_) => {
            // expect a name
            let data = match args.next().as_deref() {
                Some("-n") => match args.next() {
                    Some(val) => Ok(ContactOp {
                        name: val,
                        key_path: None,
                    }),
                    None => Err(QryptexError::new_cli(CliErrorKind::MissingNameValue)),
                },
                Some(s) => Ok(ContactOp {
                    name: String::from_str(s).unwrap(),
                    key_path: None,
                }),
                None => Err(QryptexError::new_cli(CliErrorKind::MissingContactName)),
            }?;

            Ok(op.with_contact_data(data))
        }
        Operation::ContactList => Ok(op),
        _ => unreachable!(),
    }
}

/// Forms a valid cryptographic operation from the arguments or returns an error.
/// The error will be of type QryptexError::Cli.
/// The operation will be either Operation::Encrypt or
/// Operation::Decrypt.
fn read_crypto_command<I: Iterator<Item = String>>(
    args: &mut std::iter::Peekable<I>,
    op: Operation,
) -> Result<Operation, QryptexError> {
    let mut is_path = false;
    let mut target = String::new();
    let mut contact = String::new();
    let mut output_path = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-f" | "--file" => args.next().map_or(
                Err(QryptexError::new_cli(CliErrorKind::MissingPlaintextPath)),
                |val| {
                    is_path = true;
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
                    output_path = Some(resolve_tilde(path));
                    Ok(())
                },
            ),
            "-c" | "--contact" => args.next().map_or(
                Err(QryptexError::new_cli(CliErrorKind::MissingContactName)),
                |val| {
                    contact = val;
                    Ok(())
                },
            ),
            "--debug" => Ok(()),
            _ => {
                if let Some(s) = args.peek() {
                    match s.as_str() {
                        "--debug" => {
                            target.push_str(arg.as_str());
                            is_path = false;
                            Ok(())
                        }
                        "-f" => {
                            target.push_str(arg.as_str());
                            is_path = true;
                            Ok(())
                        }
                        _ => Err(QryptexError::new_cli(CliErrorKind::InvalidArgument)),
                    }
                } else {
                    target.push_str(arg.as_str());
                    is_path = false;
                    Ok(())
                }
            }
        }?;
    }

    if target.is_empty() {
        let kind = if is_path {
            CliErrorKind::MissingPlaintextPath
        } else {
            CliErrorKind::MissingPlaintext
        };
        Err(QryptexError::new_cli(kind))
    } else if contact.is_empty() {
        Err(QryptexError::new_cli(CliErrorKind::MissingContactName))
    } else {
        let t = match is_path {
            true => CryptoTarget::new_file(resolve_tilde(target)),
            false => CryptoTarget::new_text(target),
        };
        Ok(op.with_crypto_data(CryptoOp {
            target: t,
            contact,
            output_path,
        }))
    }
}

/// Takes a path, scans it for a '~' at the beginning.
/// If the path starts with '~', it is replaced by the current user's
/// home directory.
fn resolve_tilde<T: AsRef<Path>>(path: T) -> PathBuf {
    let p = path.as_ref();
    if path.as_ref().starts_with("~") {
        let mut new_path = home::home_dir().unwrap();
        new_path.push(p.strip_prefix("~").unwrap());
        new_path
    } else {
        PathBuf::from(p)
    }
}
