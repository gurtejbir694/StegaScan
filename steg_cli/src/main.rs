use clap::Parser;
use infer::Infer;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "stegascan",
    version = "0.1.0",
    about = "CLI to process file metadata"
)]
struct Args {
    /// Path to the file to process
    #[arg(short, long, required = true)]
    file: PathBuf,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Serialize, Debug)] // Added Debug derive
#[serde(rename_all = "lowercase")]
enum FileType {
    Audio,
    Video,
    Text,
    Image,
}

#[derive(Serialize)]
struct FileObject {
    file_path: String,
    file_size: u64,
    file_type: FileType,
    file_data: Vec<u8>,
}

fn process_file(path: &PathBuf) -> Result<FileObject, Box<dyn std::error::Error>> {
    let metadata = std::fs::metadata(&path)?;
    let file_data = std::fs::read(&path)?;
    let infer = Infer::new();
    let file_type = if let Ok(Some(kind)) = infer.get_from_path(&path) {
        match kind.mime_type() {
            mime if mime.starts_with("audio/") => FileType::Audio,
            mime if mime.starts_with("video/") => FileType::Video,
            mime if mime.starts_with("text/") || mime.starts_with("application/") => FileType::Text,
            mime if mime.starts_with("image/") => FileType::Image,
            _ => FileType::Text, // Default to Text for unclassified
        }
    } else {
        FileType::Text // Fallback for unreadable files
    };
    Ok(FileObject {
        file_path: path.to_string_lossy().into_owned(),
        file_size: metadata.len(),
        file_type,
        file_data,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let file_object = process_file(&args.file)?;
    let file_objects: Vec<FileObject> = vec![file_object];

    if args.verbose {
        println!(
            "\nVerbose Details: Path: {}, Size: {} bytes, Type: {:?}, Data Length: {} bytes",
            file_objects[0].file_path,
            file_objects[0].file_size,
            file_objects[0].file_type,
            file_objects[0].file_data.len()
        );
    }

    Ok(())
}
