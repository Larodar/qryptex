use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;

use crate::error::CryptographicError;
use crate::error::InnerError;
use crate::types::AppSettings;
use crate::types::ContactOp;
use crate::types::CryptoOp;
use crate::types::CryptoTarget;
use crate::types::ExportOp;
use crate::types::Operation;
use contacts::*;
use error::{ContactsError, ContactsErrorKind, CryptographicErrorKind, QryptexError};
use rand::prelude::StdRng;
use rand::{RngCore, SeedableRng};
use rsa::{pem::parse, pem::Pem, PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};
use std::fs;
use std::{convert::TryFrom, path::Path};

mod cli;
mod contacts;
mod error;
mod types;

/// The encrypted data has the following format:
/// Nonce|Key|Ciphertext
/// 12bytes|32bytes|...
/// These first 44 bytes are RSA encrypted and therefore
/// form a 256 byte long prefix.
fn main() {
    let (op, dbg) = match cli::read_cli_args() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    let app_settings = types::build_app_settings(dbg);
    run_command(op, app_settings);
}

fn run_command(op: Operation, app_settings: AppSettings) {
    let result = match op {
        Operation::Decrypt(context) => {
            // TODO: find a better way to do this
            decrypt(context.unwrap(), app_settings)
        }
        Operation::Encrypt(context) => encrypt(context.unwrap(), app_settings),
        Operation::Init => {
            init(app_settings).map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Io))
        }
        Operation::ContactAdd(context) => add_contact(context.unwrap(), app_settings),
        Operation::ContactRemove(context) => remove_contact(context.unwrap(), app_settings),
        Operation::ContactList => {
            let _ = app_settings
                .contacts
                .iter()
                .map(|c| println!("{}", c))
                .collect::<()>();
            Ok(())
        }
        Operation::Export(context) => export_key(context, app_settings),
    };

    handle_result(result);
}

fn handle_result(result: Result<(), QryptexError>) {
    if let Err(e) = result {
        println!("The operation resulted in an error: {}", e);
        std::process::exit(1);
    } else {
        println!("The operation finished successfully.");
    }
}

/// Exports the public key of the contact or self to the specified target location.
fn export_key(context: ExportOp, settings: AppSettings) -> Result<(), QryptexError> {
    let key_path = match context.contact {
        Some(c) => {
            // export contact
            if settings.contacts.contains(&c) {
                let mut path = settings.contacts_dir.clone();
                let mut file_name = c.clone();
                file_name.push_str(".pem");
                path.push(file_name);
                Ok(path)
            } else {
                Err(QryptexError::new_contact(ContactsErrorKind::NotFound))
            }
        }
        None => {
            // export self
            let mut path = settings.home.clone();
            path.push("_self/public.pem");
            Ok(path)
        }
    }?;

    match fs::copy(key_path, context.output_path) {
        Err(_) => Err(QryptexError::new_contact(ContactsErrorKind::NotFound)),
        Ok(0) => Err(QryptexError::new_contact(ContactsErrorKind::Io)),
        _ => Ok(()),
    }
}

/// Adds the configured contact to contacts.
/// Returns an error otherwise.
fn add_contact(context: ContactOp, app: AppSettings) -> Result<(), QryptexError> {
    if app.contacts.contains(&context.name) {
        Err(QryptexError::new_contact(ContactsErrorKind::ExistsAlready))
    } else {
        try_add_contact(
            app,
            context.name.as_str(),
            context.key_path.unwrap().as_path(),
        )
    }
}

fn try_add_contact(app: AppSettings, name: &str, key_path: &Path) -> Result<(), QryptexError> {
    // path to the key file
    let contact_path = app.contacts_dir.join(name);

    // contact name
    if Path::exists(contact_path.as_path()) {
        // TODO: handle this better, the dir may be corrupted?
        return Err(QryptexError::new_contact(ContactsErrorKind::ExistsAlready));
    }

    let bytes = fs::read(key_path).map_err(|e| {
        QryptexError::Contact(ContactsError::with_inner(
            ContactsErrorKind::Io,
            Box::new(e),
        ))
    })?;

    let _ = pub_key_from_bytes(&bytes)?;
    // assemble file content
    fs::write(contact_path, &bytes).unwrap();
    Ok(())
}

fn remove_contact(context: ContactOp, app: AppSettings) -> Result<(), QryptexError> {
    // path to the key file
    contacts::delete_contact_file(app.contacts_dir.as_path(), context.name.as_str())
        .map_err(|_| QryptexError::new_contact(ContactsErrorKind::Io))
}

fn init(settings: AppSettings) -> std::io::Result<()> {
    // create .qryptex dir to store the information
    fs::create_dir(settings.home.as_path())?;
    // create contacts dir to store the contact files
    create_dir_graceful(settings.contacts_dir.as_path())?;
    fs::create_dir(settings.local_keys_path.as_path())?;

    println!("Initialization complete.");

    // create key pair
    // TODO: figure this out
    // if linux
    // openssl genrsa --out ~/.qryptex/_self/private.pem
    // openssl rsa -in private.pem -pubout > public.pem

    Ok(())
}

fn encrypt(context: CryptoOp, app: AppSettings) -> Result<(), QryptexError> {
    let plaintext = match &context.target {
        CryptoTarget::File(path) => {
            fs::read(path).map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Io))
        }
        CryptoTarget::Text(t) => Ok(t.bytes().collect()),
    }?;
    let pub_key = load_contact(context.contact.as_str(), app)?;
    // build session key
    let (nonce, key) = generate_operation_primitives();
    // build aes cipher
    let mut cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| {
        CryptographicError::with_inner(CryptographicErrorKind::Encryption, InnerError::AesGcm(e))
    })?;
    println!("encrypting...");
    let ciphertext = encrypt_plaintext(&plaintext[..], &mut cipher, &nonce)?;
    let mut prefix = [0u8; 44];
    prefix[..12].copy_from_slice(&nonce);
    prefix[12..].copy_from_slice(&key);
    let encrypted_prefix = encrypt_primitives(&prefix, &pub_key)?;
    match &context.target {
        CryptoTarget::File(in_path) => {
            println!("{}", in_path.to_string_lossy());
            // output must be a file
            let ciphertext_path = match &context.output_path {
                Some(p) => p.clone(),
                None => in_path.with_extension("qrx"),
            };
            fs::write(ciphertext_path, ciphertext)
                .map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Io))
        }
        CryptoTarget::Text(_) => {
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
}

/// Decrypts a byte string generated by qryptex.
fn decrypt(context: CryptoOp, app: AppSettings) -> Result<(), QryptexError> {
    let prefixed_ciphertext = match &context.target {
        CryptoTarget::File(p) => {
            std::fs::read(p).map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Io))
        }
        CryptoTarget::Text(s) => hex_to_bytes(s.as_str()),
    }?;

    let (encrypted_prefix, ciphertext) = (&prefixed_ciphertext[..256], &prefixed_ciphertext[256..]);
    let path = app.local_keys_path.join("private.pem");
    let private_key = load_private_key(path.as_path())?;
    let (nonce, key) = recover_primitives(encrypted_prefix, &private_key)?;

    let mut cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let plaintext_raw = decrypt_ciphertext(ciphertext, &mut cipher, &nonce)?;
    match &context.target {
        CryptoTarget::File(in_path) => {
            // output must be a file
            let plaintext_path = match &context.output_path {
                Some(p) => p.clone(),
                None => in_path.with_extension("plain"),
            };
            std::fs::write(plaintext_path, plaintext_raw)
                .map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Io))
        }
        CryptoTarget::Text(_) => {
            // output is a small string which should be written to stdout
            let plaintext = String::from_utf8(plaintext_raw)
                .map_err(|_| QryptexError::new_crypto(CryptographicErrorKind::Format))?;
            println!("Success!\n{}", plaintext);
            Ok(())
        }
    }
}

fn recover_primitives(
    prefix: &[u8],
    private_key: &RSAPrivateKey,
) -> Result<([u8; 12], [u8; 32]), QryptexError> {
    if prefix.len() != 256 {
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
fn encrypt_primitives(prefix: &[u8], public_key: &RSAPublicKey) -> Result<Vec<u8>, QryptexError> {
    let mut rng = StdRng::from_entropy();
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    match public_key.encrypt(&mut rng, padding, prefix) {
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
        .map_err(|e| {
            CryptographicError::with_inner(
                CryptographicErrorKind::Encryption,
                InnerError::AesGcm(e),
            )
        })?;
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

fn load_contact(contact_name: &str, app: AppSettings) -> Result<RSAPublicKey, QryptexError> {
    let bytes = contacts::load_contact_key_bytes(app.contacts_dir.as_path(), contact_name)
        .map_err(|e| ContactsError::with_inner(ContactsErrorKind::Io, Box::new(e)))?;
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
