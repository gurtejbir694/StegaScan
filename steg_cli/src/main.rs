use analyzers::{Analyzer, image_filter::ImageFilterAnalyzer};
use clap::Parser;
use infer::Infer;
use parsers::{Parser as _, image_parser::ImageParser};
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
    file_path: PathBuf,
    file_size: u64,
    file_type: FileType,
}

fn process_file(path: &PathBuf) -> Result<FileObject, Box<dyn std::error::Error>> {
    let metadata = std::fs::metadata(&path)?;
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
        file_path: path.to_path_buf(),
        file_size: metadata.len(),
        file_type,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();
    let args = Args::parse();

    let file_object = process_file(&args.file)?;
    let file_objects: Vec<FileObject> = vec![file_object];

    if args.verbose {
        log::info!(
            "\nScanning file Details: Path: {:?}, Size: {} bytes, Type: {:?}",
            file_objects[0].file_path,
            file_objects[0].file_size,
            file_objects[0].file_type,
        );
    }

    std::fs::remove_dir_all("outputs/");

    std::fs::create_dir("outputs/").unwrap();

    for file_object in file_objects.into_iter() {
        match file_object.file_type {
            FileType::Audio => todo!(),
            FileType::Video => todo!(),
            FileType::Text => todo!(),
            FileType::Image => {
                let image = ImageParser::parse_path(&file_object.file_path).unwrap();
                let output = ImageFilterAnalyzer::analyze(image).unwrap();
                for (i, image) in output.iter().enumerate() {
                    image
                        .save(format!(
                            "outputs/{} - {}.avif",
                            file_object.file_path.file_name().unwrap().to_str().unwrap(),
                            i
                        ))
                        .unwrap();
                }
            }
        }
    }

    Ok(())
}
