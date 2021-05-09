use rand::rngs::OsRng;
use rsa::{pem::parse, pem::Pem, PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};
use std::fmt;
use std::{convert::TryFrom, path::Path};
use std::{error::Error, fs::File};
use std::{fmt::Display, io::prelude::*};

fn main() {
    let pub_key = match load_pub_key() {
        Err(_) => {
            eprintln!("Could not load the public key.");
            // print error
            return;
        }
        Ok(key) => key,
    };

    let params = std::env::args().collect::<Vec<String>>();
    let plaintext = params[1].as_str();
    let ciphertext = match encrypt_txt(plaintext, &pub_key) {
        Err(_) => {
            eprintln!("Could not encrypt the plaintext.");
            // print error
            return;
        }
        Ok(ciph) => ciph,
    };

    let ciphertext_str = ciphertext
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join("");
    println!("Success! Ciphertext: {}", ciphertext_str);

    let private_key = match load_private_key() {
        Err(_) => {
            eprintln!("Could not load private key.");
            // print error
            return;
        }
        Ok(key) => key,
    };

    let dec_plaintext = match decrypt_ciphertext(ciphertext_str.as_str(), &private_key) {
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
