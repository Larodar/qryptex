use std::fs;
use std::io;
use std::io::ErrorKind;
use std::path::Path;

pub fn load_contact_names(contact_dir: &Path) -> io::Result<Vec<String>> {
    let paths = fs::read_dir(contact_dir)?;
    let mut contact_names = vec![];
    for entry_result in paths {
        let entry = entry_result?;
        let file_name = match entry.file_name().into_string() {
            Ok(valid) => valid,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Cannot read the contact file. Invalid Unicode characters.",
                ))
            }
        };
        contact_names.push(file_name);
    }

    Ok(contact_names)
}

pub fn load_contact_key_bytes(contact_dir: &Path, contact_name: &str) -> io::Result<Vec<u8>> {
    let path = contact_dir.join(contact_name);
    let buff = fs::read(path)?;
    Ok(buff)
}

pub fn delete_contact_file(contact_dir: &Path, contact_name: &str) -> io::Result<()> {
    let path = contact_dir.join(contact_name);
    fs::remove_file(path)
}

/// This function tries to create the directory specified by the path.
/// If the path already exists, nothing is done.
pub fn create_dir_graceful(contact_dir: &Path) -> io::Result<()> {
    match fs::create_dir(contact_dir) {
        Ok(_) => Ok(()),
        Err(e) => match e.kind() {
            ErrorKind::AlreadyExists => Ok(()),
            _ => Err(e),
        },
    }
}
