use analyzers::{
    Analyzer, exif_analyzer::ExifAnalyzerWithPath, id3_analyzer::Id3AnalyzerWithPath,
    image_filter::ImageFilterAnalyzer, lsb_analyzer::LsbAnalyzer,
    magic_bytes_analyzer::MagicBytesAnalyzerWithPath, spectrogram_analyzer::SpectrogramAnalyzer,
};
use clap::Parser;
use infer::Infer;
use parsers::{
    Parser as _, audio_parser::AudioParser, image_parser::ImageParser, text_parser::TextParser,
    video_parser::VideoParser,
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

    // Run Magic Bytes Analysis FIRST on all files
    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║          MAGIC BYTES / BINWALK ANALYSIS                  ║");
    println!("╚═══════════════════════════════════════════════════════════╝");

    match MagicBytesAnalyzerWithPath::new(&file_objects[0].file_path).analyze() {
        Ok(analysis) => {
            println!("Primary format: {}", analysis.primary_format);
            if let Some(expected) = &analysis.expected_format {
                println!("Expected format (by extension): {}", expected);
            }
            println!(
                "Total signatures found: {}",
                analysis.total_signatures_found
            );
            println!(
                "Multiple formats detected: {}",
                analysis.has_multiple_formats
            );

            // Show format summary
            println!("\n--- Format Summary ---");
            println!("Images: {}", analysis.format_summary.image_files);
            println!("Audio: {}", analysis.format_summary.audio_files);
            println!("Video: {}", analysis.format_summary.video_files);
            println!("Text/Documents: {}", analysis.format_summary.text_files);
            println!("Archives: {}", analysis.format_summary.archive_files);
            println!("Executables: {}", analysis.format_summary.executable_files);
            println!("Other: {}", analysis.format_summary.other_files);

            // Show embedded files
            if !analysis.embedded_files.is_empty() {
                println!("\n--- Embedded Files Detected ---");
                for (idx, file) in analysis.embedded_files.iter().enumerate() {
                    println!(
                        "  {}. Offset: 0x{:X} ({})",
                        idx + 1,
                        file.offset,
                        file.offset
                    );
                    println!("     Type: {}", file.file_type);
                    println!("     Description: {}", file.description);
                    println!("     Confidence: {}", file.confidence);
                }
            }

            // Show suspicious findings
            if !analysis.suspicious_findings.is_empty() {
                println!("\n⚠️  SUSPICIOUS FINDINGS:");
                for finding in &analysis.suspicious_findings {
                    println!("  🚩 {}", finding);
                }
            }

            if analysis.has_suspicious_data {
                println!("\n⚠️  WARNING: This file contains data that may indicate steganography!");
            }
        }
        Err(e) => {
            log::error!("Magic bytes analysis failed: {}", e);
        }
    }

    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║          FORMAT-SPECIFIC ANALYSIS                        ║");
    println!("╚═══════════════════════════════════════════════════════════╝\n");

    for file_object in file_objects.into_iter() {
        match file_object.file_type {
            FileType::Audio => {
                match AudioParser::parse_path(&file_object.file_path) {
                    Ok(samples) => {
                        if args.verbose {
                            log::info!("Audio samples length: {}", samples.len());
                        }

                        println!("Processed {} audio samples successfully", samples.len());

                        // ID3 Tag Analysis
                        println!("\n=== ID3 Tag Analysis ===");
                        match Id3AnalyzerWithPath::new(&file_object.file_path).analyze() {
                            Ok(id3_data) => {
                                if let Some(title) = &id3_data.title {
                                    println!("Title: {}", title);
                                }
                                if let Some(artist) = &id3_data.artist {
                                    println!("Artist: {}", artist);
                                }

                                println!("Comments: {}", id3_data.comments.len());
                                println!("Pictures: {}", id3_data.pictures.len());
                                println!("Private frames: {}", id3_data.private_frames.len());

                                if !id3_data.suspicious_frames.is_empty() {
                                    println!("\n⚠️  Suspicious findings:");
                                    for finding in &id3_data.suspicious_frames {
                                        println!("  - {}", finding);
                                    }
                                }

                                if args.verbose {
                                    println!("\nAll ID3 frames:");
                                    for (key, value) in &id3_data.all_frames {
                                        println!("  {}: {}", key, value);
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!("ID3 analysis failed: {}", e);
                            }
                        }

                        // Spectrogram Analysis
                        println!("\n=== Spectrogram Analysis ===");
                        match SpectrogramAnalyzer::analyze(samples) {
                            Ok(spectrogram_data) => {
                                println!(
                                    "High frequency energy: {:.4}",
                                    spectrogram_data.high_frequency_energy
                                );
                                println!(
                                    "Hidden message detected: {}",
                                    spectrogram_data.has_hidden_message
                                );

                                if !spectrogram_data.suspicious_patterns.is_empty() {
                                    println!("\n⚠️  Suspicious patterns:");
                                    for pattern in &spectrogram_data.suspicious_patterns {
                                        println!("  - {}", pattern);
                                    }
                                }

                                // Save spectrogram image
                                let fname =
                                    file_object.file_path.file_name().unwrap().to_str().unwrap();
                                spectrogram_data
                                    .spectrogram_image
                                    .save(format!("outputs/{}_spectrogram.png", fname))
                                    .unwrap();
                                println!("Spectrogram saved to outputs/{}_spectrogram.png", fname);
                            }
                            Err(e) => {
                                log::error!("Spectrogram analysis failed: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Error parsing audio file: {:?}", e);
                        if args.verbose {
                            eprintln!("Detailed error: {:?}", e);
                        }
                        return Err(Box::new(e));
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
            FileType::Text => {
                match TextParser::parse_path(&file_object.file_path) {
                    Ok(text_content) => {
                        println!("\n=== Text File Analysis ===");
                        println!("File type: {}", text_content.file_type);
                        println!("Lines: {}", text_content.line_count);
                        println!("Words: {}", text_content.word_count);
                        println!("Characters: {}", text_content.char_count);
                        println!("Size: {} bytes", text_content.byte_size);

                        if args.verbose {
                            log::info!(
                                "Text file stats - Lines: {}, Words: {}, Chars: {}, Bytes: {}",
                                text_content.line_count,
                                text_content.word_count,
                                text_content.char_count,
                                text_content.byte_size
                            );

                            // Show first 500 characters
                            if text_content.content.len() > 500 {
                                println!("\nFirst 500 characters:");
                                println!("{}", &text_content.content[..500]);
                                println!("...");
                            } else {
                                println!("\nContent:");
                                println!("{}", text_content.content);
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Error parsing text file: {:?}", e);
                        return Err(Box::new(e));
                    }
                }
            }
            FileType::Image => {
                let image = ImageParser::parse_path(&file_object.file_path).unwrap();

                println!("\n=== Image Analysis ===");

                // EXIF Metadata Analysis
                println!("\n--- EXIF Metadata ---");
                match ExifAnalyzerWithPath::new(&file_object.file_path).analyze() {
                    Ok(exif_data) => {
                        println!("EXIF fields found: {}", exif_data.metadata.len());
                        println!("Has thumbnail: {}", exif_data.has_thumbnail);

                        if let Some(size) = exif_data.thumbnail_size {
                            println!("Thumbnail size: {} bytes", size);
                        }

                        if !exif_data.comment_fields.is_empty() {
                            println!("\nComment fields:");
                            for comment in &exif_data.comment_fields {
                                println!("  {}", comment);
                            }
                        }

                        if !exif_data.suspicious_fields.is_empty() {
                            println!("\n⚠️  Suspicious EXIF findings:");
                            for finding in &exif_data.suspicious_fields {
                                println!("  - {}", finding);
                            }
                        }

                        if args.verbose && !exif_data.metadata.is_empty() {
                            println!("\nAll EXIF data:");
                            for (key, value) in &exif_data.metadata {
                                println!("  {}: {}", key, value);
                            }
                        }
                    }
                    Err(e) => {
                        if args.verbose {
                            log::info!(
                                "EXIF analysis skipped: {} (format may not support EXIF)",
                                e
                            );
                        } else {
                            println!("No EXIF data found (format may not support EXIF metadata)");
                        }
                    }
                }

                // LSB Analysis
                println!("\n--- LSB Steganography Analysis ---");
                match LsbAnalyzer::analyze(image.clone()) {
                    Ok(lsb_analysis) => {
                        println!("Suspicious: {}", lsb_analysis.suspicious);

                        for (i, score) in lsb_analysis.chi_square_scores.iter().enumerate() {
                            let channel = match i {
                                0 => "Red",
                                1 => "Green",
                                2 => "Blue",
                                _ => "Unknown",
                            };
                            println!(
                                "  {} channel - Chi-square: {:.2}, Entropy: {:.4}",
                                channel, score, lsb_analysis.entropy_scores[i]
                            );
                        }

                        if lsb_analysis.suspicious {
                            println!("\n⚠️  LSB analysis indicates possible hidden data!");
                        }

                        // Save LSB plane visualizations
                        let fname = file_object.file_path.file_name().unwrap().to_str().unwrap();
                        for (i, lsb_plane) in lsb_analysis.lsb_planes.iter().enumerate() {
                            let channel = match i {
                                0 => "red",
                                1 => "green",
                                2 => "blue",
                                _ => "unknown",
                            };
                            lsb_plane
                                .save(format!("outputs/{}_lsb_{}.png", fname, channel))
                                .unwrap();
                        }
                        println!("LSB plane images saved to outputs/");
                    }
                    Err(e) => {
                        log::error!("LSB analysis failed: {}", e);
                    }
                }

                // Image Filter Analysis (original functionality)
                println!("\n--- Image Filter Analysis ---");
                if args.verbose {
                    log::info!("Generating filtered images...");
                }

                match ImageFilterAnalyzer::analyze(image) {
                    Ok(output) => {
                        for (i, img) in output.iter().enumerate() {
                            if args.verbose && i % 2 == 0 {
                                log::info!("Saving filter {} of {}...", i + 1, output.len());
                            }
                            img.save(format!(
                                "outputs/{}_filter_{}.avif",
                                file_object.file_path.file_name().unwrap().to_str().unwrap(),
                                i
                            ))
                            .unwrap();
                        }
                        println!("Generated {} filtered images", output.len());
                    }
                    Err(e) => {
                        log::error!("Image filter analysis failed: {:?}", e);
                    }
                }
            }
        }
    }

    Ok(())
}
