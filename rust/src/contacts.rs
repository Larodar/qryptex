use std::fs;
use std::path::Path;

pub fn load_contact_names(contact_dir: &Path) -> std::io::Result<Vec<String>> {
    let paths = std::fs::read_dir(contact_dir)?;
    let mut contact_names = vec![];
    for entry_result in paths {
        let entry = entry_result?;
        let file_name = match entry.file_name().into_string() {
            Ok(valid) => valid,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Cannot read the contact file. Invalid Unicode characters.",
                ))
            }
        };
        contact_names.push(file_name);
    }

    Ok(contact_names)
}

pub fn load_contact_key_bytes(contact_dir: &Path, contact_name: &str) -> std::io::Result<Vec<u8>> {
    let path = contact_dir.join(contact_name);
    dbg!(&path);
    let buff = fs::read(path)?;
    Ok(buff)
}

pub fn delete_contact_file(contact_dir: &Path, contact_name: &str) -> std::io::Result<()> {
    let path = contact_dir.join(contact_name);
    if !Path::exists(path.as_path()) {
        return Ok(());
    }

    fs::remove_file(path)
}

pub fn init_contacts_dir(contact_dir: &Path) -> std::io::Result<()> {
    dbg!(contact_dir);
    fs::create_dir(contact_dir)
}
