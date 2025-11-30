use analyzers::{
    Analyzer, exif_analyzer::ExifAnalyzerWithPath, id3_analyzer::Id3AnalyzerWithPath,
    image_filter::ImageFilterAnalyzer, lsb_analyzer::LsbAnalyzer,
    magic_bytes_analyzer::MagicBytesAnalyzerWithPath, spectrogram_analyzer::SpectrogramAnalyzer,
    video_frame_analyzer::VideoFrameAnalyzer,
};
use clap::Parser;
use infer::Infer;
use parsers::{
    Parser as _, audio_parser::AudioParser, image_parser::ImageParser, text_parser::TextParser,
    video_parser::VideoParser,
};
use serde::Serialize;
use std::path::PathBuf;

mod json_report;
use json_report::*;

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

    /// Output path for JSON report
    #[arg(short, long, default_value = "outputs/report.json")]
    output: String,

    /// Number of video frames to sample (analyze every Nth frame)
    #[arg(long, default_value = "30")]
    video_sample_rate: usize,
}

#[derive(Serialize, Debug)]
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
                if path.extension().and_then(|ext| ext.to_str()) == Some("wma") {
                    FileType::Audio
                } else {
                    FileType::Text
                }
            }
        }
    } else {
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

    // Initialize JSON report
    let detected_type = match file_objects[0].file_type {
        FileType::Audio => "Audio",
        FileType::Video => "Video",
        FileType::Text => "Text",
        FileType::Image => "Image",
    };

    let mut report = SteganalysisReport::new(
        &file_objects[0].file_path,
        file_objects[0].file_size,
        detected_type.to_string(),
    );

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

            println!("\n--- Format Summary ---");
            println!("Images: {}", analysis.format_summary.image_files);
            println!("Audio: {}", analysis.format_summary.audio_files);
            println!("Video: {}", analysis.format_summary.video_files);
            println!("Text/Documents: {}", analysis.format_summary.text_files);
            println!("Archives: {}", analysis.format_summary.archive_files);
            println!("Executables: {}", analysis.format_summary.executable_files);
            println!("Other: {}", analysis.format_summary.other_files);

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

            if !analysis.suspicious_findings.is_empty() {
                println!("\n⚠️  SUSPICIOUS FINDINGS:");
                for finding in &analysis.suspicious_findings {
                    println!("  🚩 {}", finding);
                }
            }

            if analysis.has_suspicious_data {
                println!("\n⚠️  WARNING: This file contains data that may indicate steganography!");
            }

            // Populate JSON report with magic bytes analysis
            let magic_report = MagicBytesReport {
                primary_format: analysis.primary_format.clone(),
                expected_format: analysis.expected_format.clone(),
                total_signatures_found: analysis.total_signatures_found,
                has_multiple_formats: analysis.has_multiple_formats,
                has_suspicious_data: analysis.has_suspicious_data,
                format_summary: FormatSummary {
                    images: analysis.format_summary.image_files,
                    audio: analysis.format_summary.audio_files,
                    video: analysis.format_summary.video_files,
                    text_documents: analysis.format_summary.text_files,
                    archives: analysis.format_summary.archive_files,
                    executables: analysis.format_summary.executable_files,
                    other: analysis.format_summary.other_files,
                },
                embedded_files: analysis
                    .embedded_files
                    .iter()
                    .map(|f| EmbeddedFileInfo {
                        offset: f.offset,
                        offset_hex: format!("0x{:X}", f.offset),
                        description: f.description.clone(),
                        file_type: f.file_type.clone(),
                        confidence: f.confidence.clone(),
                    })
                    .collect(),
                suspicious_findings: analysis.suspicious_findings.clone(),
            };
            report.set_magic_bytes_analysis(magic_report);
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

                        let mut audio_analysis = AudioAnalysis {
                            sample_count: samples.len(),
                            id3_analysis: None,
                            spectrogram_analysis: None,
                        };

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

                                audio_analysis.id3_analysis = Some(Id3Report {
                                    title: id3_data.title.clone(),
                                    artist: id3_data.artist.clone(),
                                    album: id3_data.album.clone(),
                                    year: id3_data.year,
                                    comments_count: id3_data.comments.len(),
                                    pictures_count: id3_data.pictures.len(),
                                    private_frames_count: id3_data.private_frames.len(),
                                    suspicious_frames: id3_data.suspicious_frames.clone(),
                                });
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

                                let fname =
                                    file_object.file_path.file_name().unwrap().to_str().unwrap();
                                let output_file = format!("outputs/{}_spectrogram.png", fname);
                                spectrogram_data
                                    .spectrogram_image
                                    .save(&output_file)
                                    .unwrap();
                                println!("Spectrogram saved to {}", output_file);

                                audio_analysis.spectrogram_analysis = Some(SpectrogramReport {
                                    high_frequency_energy: spectrogram_data.high_frequency_energy,
                                    hidden_message_detected: spectrogram_data.has_hidden_message,
                                    suspicious_patterns: spectrogram_data
                                        .suspicious_patterns
                                        .clone(),
                                    output_file,
                                });
                            }
                            Err(e) => {
                                log::error!("Spectrogram analysis failed: {}", e);
                            }
                        }

                        report.set_format_analysis(FormatSpecificAnalysis::Audio(audio_analysis));
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
                        let mut suspicious_frame_indices = Vec::new();
                        let mut total_entropy = 0.0;
                        let mut frames_analyzed = 0;

                        println!("\n=== Video Frame Analysis ===");
                        println!(
                            "Sampling every {} frames for steganography analysis",
                            args.video_sample_rate
                        );

                        for (idx, frame_result) in frame_iter.enumerate() {
                            match frame_result {
                                Ok(frame) => {
                                    frame_count += 1;

                                    if args.verbose && idx % 100 == 0 {
                                        log::info!("Processing frame {}...", idx);
                                    }

                                    // Perform detailed analysis on sampled frames
                                    if idx % args.video_sample_rate == 0 {
                                        let dynamic_image = image::DynamicImage::ImageRgba8(frame);

                                        match VideoFrameAnalyzer::analyze(dynamic_image) {
                                            Ok(mut analysis) => {
                                                analysis.frame_index = idx;
                                                frames_analyzed += 1;

                                                // Collect entropy for averaging
                                                let avg_entropy: f64 =
                                                    analysis.entropy_scores.iter().sum::<f64>()
                                                        / analysis.entropy_scores.len() as f64;
                                                total_entropy += avg_entropy;

                                                // Track anomalies
                                                if analysis.lsb_suspicious
                                                    || analysis.histogram_anomalies
                                                {
                                                    suspicious_frame_indices.push(idx);

                                                    if args.verbose {
                                                        println!(
                                                            "\n⚠️  Suspicious frame {} detected:",
                                                            idx
                                                        );
                                                        println!(
                                                            "   LSB suspicious: {}",
                                                            analysis.lsb_suspicious
                                                        );
                                                        println!(
                                                            "   Histogram anomalies: {}",
                                                            analysis.histogram_anomalies
                                                        );
                                                        println!(
                                                            "   Edge density: {:.4}",
                                                            analysis.edge_density
                                                        );
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                log::warn!("Frame {} analysis failed: {}", idx, e);
                                            }
                                        }
                                    }
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

                        let avg_entropy = if frames_analyzed > 0 {
                            total_entropy / frames_analyzed as f64
                        } else {
                            0.0
                        };

                        if args.verbose {
                            log::info!(
                                "Video processing complete: {} frames total, {} frames analyzed, {} errors",
                                frame_count,
                                frames_analyzed,
                                error_count
                            );
                        }

                        println!("\n--- Video Analysis Summary ---");
                        println!("Total frames: {}", frame_count);
                        println!("Frames analyzed: {}", frames_analyzed);
                        println!("Suspicious frames: {}", suspicious_frame_indices.len());
                        println!("Average entropy: {:.4}", avg_entropy);
                        println!("Errors encountered: {}", error_count);

                        if !suspicious_frame_indices.is_empty() {
                            println!(
                                "\n⚠️  Suspicious frames at indices: {:?}",
                                suspicious_frame_indices
                            );
                            println!("Consider extracting these frames for detailed analysis");
                        }

                        report.set_format_analysis(FormatSpecificAnalysis::Video(VideoAnalysis {
                            frames_processed: frame_count,
                            errors_encountered: error_count,
                        }));
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
            FileType::Text => match TextParser::parse_path(&file_object.file_path) {
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

                        if text_content.content.len() > 500 {
                            println!("\nFirst 500 characters:");
                            println!("{}", &text_content.content[..500]);
                            println!("...");
                        } else {
                            println!("\nContent:");
                            println!("{}", text_content.content);
                        }
                    }

                    report.set_format_analysis(FormatSpecificAnalysis::Text(TextAnalysis {
                        file_type: text_content.file_type.clone(),
                        line_count: text_content.line_count,
                        word_count: text_content.word_count,
                        character_count: text_content.char_count,
                        size_bytes: text_content.byte_size,
                    }));
                }
                Err(e) => {
                    log::error!("Error parsing text file: {:?}", e);
                    return Err(Box::new(e));
                }
            },
            FileType::Image => {
                let image = match ImageParser::parse_path(&file_object.file_path) {
                    Ok(image) => image,
                    Err(err) => {
                        log::error!("Error while reading image: {err}");
                        continue;
                    }
                };

                println!("\n=== Image Analysis ===");

                let mut image_analysis = ImageAnalysis {
                    exif_metadata: None,
                    lsb_analysis: None,
                    filter_analysis: FilterAnalysisReport {
                        filters_generated: 0,
                        output_files: Vec::new(),
                    },
                };

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

                        image_analysis.exif_metadata = Some(ExifReport {
                            fields_found: exif_data.metadata.len(),
                            has_thumbnail: exif_data.has_thumbnail,
                            thumbnail_size_bytes: exif_data.thumbnail_size,
                            comment_fields: exif_data.comment_fields.clone(),
                            suspicious_fields: exif_data.suspicious_fields.clone(),
                            metadata: exif_data
                                .metadata
                                .iter()
                                .map(|(k, v)| MetadataField {
                                    key: k.clone(),
                                    value: v.clone(),
                                })
                                .collect(),
                        });
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

                        let mut lsb_channels = Vec::new();
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

                            lsb_channels.push(LsbChannelAnalysis {
                                channel_name: channel.to_string(),
                                chi_square_score: *score,
                                entropy_score: lsb_analysis.entropy_scores[i],
                            });
                        }

                        if lsb_analysis.suspicious {
                            println!("\n⚠️  LSB analysis indicates possible hidden data!");
                        }

                        let fname = file_object.file_path.file_name().unwrap().to_str().unwrap();
                        let mut lsb_output_files = Vec::new();
                        for (i, lsb_plane) in lsb_analysis.lsb_planes.iter().enumerate() {
                            let channel = match i {
                                0 => "red",
                                1 => "green",
                                2 => "blue",
                                _ => "unknown",
                            };
                            let output_file = format!("outputs/{}_lsb_{}.png", fname, channel);
                            lsb_plane.save(&output_file).unwrap();
                            lsb_output_files.push(output_file);
                        }
                        println!("LSB plane images saved to outputs/");

                        image_analysis.lsb_analysis = Some(LsbReport {
                            is_suspicious: lsb_analysis.suspicious,
                            channels: lsb_channels,
                            output_files: lsb_output_files,
                        });
                    }
                    Err(e) => {
                        log::error!("LSB analysis failed: {}", e);
                    }
                }

                // Image Filter Analysis
                println!("\n--- Image Filter Analysis ---");
                if args.verbose {
                    log::info!("Generating filtered images...");
                }

                match ImageFilterAnalyzer::analyze(image) {
                    Ok(output) => {
                        let mut filter_files = Vec::new();
                        for (i, img) in output.iter().enumerate() {
                            if args.verbose && i % 2 == 0 {
                                log::info!("Saving filter {} of {}...", i + 1, output.len());
                            }
                            let filter_file = format!(
                                "outputs/{}_filter_{}.avif",
                                file_object.file_path.file_name().unwrap().to_str().unwrap(),
                                i
                            );
                            img.save(&filter_file).unwrap();
                            filter_files.push(filter_file);
                        }
                        println!("Generated {} filtered images", output.len());

                        image_analysis.filter_analysis = FilterAnalysisReport {
                            filters_generated: output.len(),
                            output_files: filter_files,
                        };
                    }
                    Err(e) => {
                        log::error!("Image filter analysis failed: {:?}", e);
                    }
                }

                report.set_format_analysis(FormatSpecificAnalysis::Image(image_analysis));
            }
        }
    }

    // Finalize and save report
    report.finalize_summary();

    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║          ANALYSIS SUMMARY                                ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!(
        "Steganography detected: {}",
        report.summary.steganography_detected
    );
    println!("Confidence level: {}", report.summary.confidence_level);

    if !report.summary.threat_indicators.is_empty() {
        println!("\nThreat indicators:");
        for indicator in &report.summary.threat_indicators {
            println!("  - {}", indicator);
        }
    }

    println!("\nRecommendations:");
    for recommendation in &report.summary.recommendations {
        println!("  - {}", recommendation);
    }

    match report.save_to_file(&args.output) {
        Ok(_) => {
            println!("\n✅ JSON report saved to: {}", args.output);
        }
        Err(e) => {
            log::error!("Failed to save JSON report: {}", e);
        }
    }

    Ok(())
}
