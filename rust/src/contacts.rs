use super::*;

fn load_contacts(contact_dir: &Path) -> std::io::Result<Vec<String>> {
    let paths = std::fs::read_dir(contact_dir)?;
    let mut contact_names = vec![];
    for entry_result in paths {
        let entry = entry_result?;
        let file_name = match entry.file_name().into_string() {
            Ok(valid) => valid,
            Err(invalid) => {
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
