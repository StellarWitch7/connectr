use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use actix_files::NamedFile;
use crate::ROOT_PATH;

pub fn get_file(path: &Path) -> NamedFile {
    let clean_path = path.to_str().unwrap().to_string().replace("\\", "/")
        .replace("../", "")
        .replace("./", "")
        .replace("%20", " ");
    let mut final_path = PathBuf::from(shellexpand::tilde(ROOT_PATH.to_str().unwrap()).to_string());

    final_path.push(clean_path);
    NamedFile::open(final_path).expect(format!("Failed to open {:?}", path).as_str())
}

pub fn get_file_mime(path: &Path) -> &str {
    let ext = path.extension()
        .and_then(OsStr::to_str)
        .unwrap();

    match ext {
        "txt" | "log" | "conf" => "text/plain",
        "html" => "text/html",
        "css" => "text/css",
        "js" => "text/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        "weba" => "audio/webm",
        "webm" => "video/webm",
        "webp" => "image/webp",
        _ => "application/octet-stream",
    }
}