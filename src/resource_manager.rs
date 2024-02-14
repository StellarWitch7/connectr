use std::path::Path;
use actix_files::NamedFile;

pub fn get_file(path: &Path, root: &Path) -> NamedFile {
    let clean_path = path.to_str().unwrap().to_string().replace("\\", "/")
        .replace("../", "")
        .replace("./", "")
        .replace("%20", " ");

    let mut final_path = root.to_path_buf();
    final_path.push("www");
    final_path.push(clean_path);
    NamedFile::open(final_path).expect(format!("Failed to open {:?}", path).as_str())
}