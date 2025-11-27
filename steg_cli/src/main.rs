use analyzers::{Analyzer, image_filter::ImageFilterAnalyzer};
use clap::Parser;
use image::DynamicImage;
use infer::Infer;
use parsers::{
    Parser as _, audio_parser::AudioParser, image_parser::ImageParser, video_parser::VideoParser,
};
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
            _ => {
                // Fallback for unrecognized types (e.g., WMA)
                if path.extension().and_then(|ext| ext.to_str()) == Some("wma") {
                    FileType::Audio
                } else {
                    FileType::Text // Default for unclassified
                }
            }
        }
    } else {
        // Fallback for unreadable files
        if path.extension().and_then(|ext| ext.to_str()) == Some("wma") {
            FileType::Audio
        } else {
            FileType::Text
        }
    };
    Ok(FileObject {
        file_path: path.to_path_buf(),
        file_size: metadata.len(),
        file_type,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Info)
        .init();
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

    let _ = std::fs::remove_dir_all("outputs/");

    std::fs::create_dir("outputs/").unwrap();

    for file_object in file_objects.into_iter() {
        match file_object.file_type {
            FileType::Audio => {
                match AudioParser::parse_path(&file_object.file_path) {
                    Ok(samples) => {
                        if args.verbose {
                            log::info!("Audio samples length: {}", samples.len());
                        }
                        // Placeholder for future audio analysis
                        println!("Processed {} audio samples successfully", samples.len());
                    }
                    Err(e) => {
                        log::error!("Error parsing audio file: {:?}", e);
                        if args.verbose {
                            eprintln!("Detailed error: {:?}", e);
                        }
                        return Err(Box::new(e)); // Propagate the error
                    }
                }
            }
            FileType::Video => {
                match VideoParser::parse_path(&file_object.file_path) {
                    Ok(frame_iter) => {
                        let mut frame_count = 0;
                        let mut error_count = 0;

                        for (idx, frame_result) in frame_iter.enumerate() {
                            match frame_result {
                                Ok(_frame) => {
                                    frame_count += 1;

                                    if args.verbose && idx % 100 == 0 {
                                        log::info!("Processing frame {}...", idx);
                                    }

                                    // TODO: Add video frame analyzers here
                                    // Example:
                                    // let dynamic_image = DynamicImage::ImageRgba8(frame);
                                    // let output = ImageFilterAnalyzer::analyze(dynamic_image).unwrap_or_default();
                                }
                                Err(e) => {
                                    error_count += 1;
                                    log::error!("Error decoding frame {}: {:?}", idx, e);
                                    if args.verbose {
                                        eprintln!("Detailed frame decode error: {:?}", e);
                                    }
                                }
                            }
                        }

                        if args.verbose {
                            log::info!(
                                "Video processing complete: {} frames successfully processed, {} errors",
                                frame_count,
                                error_count
                            );
                        }
                        println!(
                            "Processed {} video frames ({} errors)",
                            frame_count, error_count
                        );
                    }
                    Err(e) => {
                        log::error!("Error parsing video file: {:?}", e);
                        if args.verbose {
                            eprintln!("Detailed error: {:?}", e);
                        }
                        return Err(Box::new(e));
                    }
                }
            }
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
