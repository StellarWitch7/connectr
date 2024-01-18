use std::path::{Path, PathBuf};
use actix_files::NamedFile;
use crate::ROOT_PATH;

pub fn get_file(path: &Path) -> NamedFile {
    let clean_path = path.to_str().unwrap().to_string().replace("\\", "/")
        .replace("../", "")
        .replace("./", "")
        .replace("%20", " ");
    let mut final_path = PathBuf::from(ROOT_PATH.clone());

    final_path.push("www");
    final_path.push(clean_path);
    NamedFile::open(final_path).expect(format!("Failed to open {:?}", path).as_str())
}