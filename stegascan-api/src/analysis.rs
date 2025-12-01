use analyzers::{
    Analyzer, exif_analyzer::ExifAnalyzerWithPath, id3_analyzer::Id3AnalyzerWithPath,
    lsb_analyzer::LsbAnalyzer, magic_bytes_analyzer::MagicBytesAnalyzerWithPath,
    spectrogram_analyzer::SpectrogramAnalyzer, video_frame_analyzer::VideoFrameAnalyzer,
};
use infer::Infer;
use parsers::{
    Parser as _, audio_parser::AudioParser, image_parser::ImageParser, text_parser::TextParser,
    video_parser::VideoParser,
};
use std::path::Path;

use crate::error::ApiError;
use crate::models::*;

enum FileType {
    Audio,
    Video,
    Text,
    Image,
}

pub async fn run_full_analysis(
    file_path: &Path,
    video_sample_rate: usize,
    _verbose: bool,
) -> Result<AnalysisResponse, ApiError> {
    // Get file metadata
    let metadata = tokio::fs::metadata(file_path).await?;
    let file_size = metadata.len();

    // Detect file type
    let file_data = tokio::fs::read(file_path).await?;
    let infer = Infer::new();
    let file_type = if let Some(kind) = infer.get(&file_data) {
        match kind.mime_type() {
            mime if mime.starts_with("audio/") => FileType::Audio,
            mime if mime.starts_with("video/") => FileType::Video,
            mime if mime.starts_with("text/") || mime.starts_with("application/") => FileType::Text,
            mime if mime.starts_with("image/") => FileType::Image,
            _ => FileType::Text,
        }
    } else {
        FileType::Text
    };

    let detected_type = match file_type {
        FileType::Audio => "Audio",
        FileType::Video => "Video",
        FileType::Text => "Text",
        FileType::Image => "Image",
    };

    let extension = file_path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_string());

    let mut response = AnalysisResponse {
        file_info: FileInfo {
            path: file_path.to_string_lossy().to_string(),
            size_bytes: file_size,
            detected_type: detected_type.to_string(),
            extension,
        },
        magic_bytes_analysis: None,
        format_specific_analysis: FormatSpecificAnalysis::Unknown,
        timestamp: chrono::Utc::now().to_rfc3339(),
        summary: AnalysisSummary {
            steganography_detected: false,
            confidence_level: "low".to_string(),
            threat_indicators: Vec::new(),
            recommendations: Vec::new(),
        },
    };

    // Magic bytes analysis
    if let Ok(magic_analysis) = MagicBytesAnalyzerWithPath::new(file_path).analyze() {
        response.magic_bytes_analysis = Some(MagicBytesReport {
            primary_format: magic_analysis.primary_format,
            expected_format: magic_analysis.expected_format,
            total_signatures_found: magic_analysis.total_signatures_found,
            has_multiple_formats: magic_analysis.has_multiple_formats,
            has_suspicious_data: magic_analysis.has_suspicious_data,
            format_summary: FormatSummary {
                images: magic_analysis.format_summary.image_files,
                audio: magic_analysis.format_summary.audio_files,
                video: magic_analysis.format_summary.video_files,
                text_documents: magic_analysis.format_summary.text_files,
                archives: magic_analysis.format_summary.archive_files,
                executables: magic_analysis.format_summary.executable_files,
                other: magic_analysis.format_summary.other_files,
            },
            embedded_files: magic_analysis
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
            suspicious_findings: magic_analysis.suspicious_findings,
        });
    }

    // Format-specific analysis
    match file_type {
        FileType::Image => {
            if let Ok(image) = ImageParser::parse_path(&file_path) {
                let dimensions = ImageDimensions {
                    width: image.width(),
                    height: image.height(),
                };

                let mut image_analysis = ImageAnalysis {
                    exif_metadata: None,
                    lsb_analysis: None,
                    dimensions,
                };

                // EXIF
                if let Ok(exif_data) = ExifAnalyzerWithPath::new(file_path).analyze() {
                    image_analysis.exif_metadata = Some(ExifReport {
                        fields_found: exif_data.metadata.len(),
                        has_thumbnail: exif_data.has_thumbnail,
                        thumbnail_size_bytes: exif_data.thumbnail_size,
                        comment_fields: exif_data.comment_fields,
                        suspicious_fields: exif_data.suspicious_fields,
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

                // LSB
                if let Ok(lsb_analysis) = LsbAnalyzer::analyze(image) {
                    let channels = lsb_analysis
                        .chi_square_scores
                        .iter()
                        .enumerate()
                        .map(|(i, score)| {
                            let channel = match i {
                                0 => "Red",
                                1 => "Green",
                                2 => "Blue",
                                _ => "Unknown",
                            };
                            LsbChannelAnalysis {
                                channel_name: channel.to_string(),
                                chi_square_score: *score,
                                entropy_score: lsb_analysis.entropy_scores[i],
                            }
                        })
                        .collect();

                    image_analysis.lsb_analysis = Some(LsbReport {
                        is_suspicious: lsb_analysis.suspicious,
                        channels,
                    });
                }

                response.format_specific_analysis = FormatSpecificAnalysis::Image(image_analysis);
            }
        }
        FileType::Audio => {
            if let Ok(samples) = AudioParser::parse_path(&file_path) {
                let mut audio_analysis = AudioAnalysis {
                    sample_count: samples.len(),
                    id3_analysis: None,
                    spectrogram_analysis: None,
                };

                // ID3
                if let Ok(id3_data) = Id3AnalyzerWithPath::new(file_path).analyze() {
                    audio_analysis.id3_analysis = Some(Id3Report {
                        title: id3_data.title,
                        artist: id3_data.artist,
                        album: id3_data.album,
                        year: id3_data.year,
                        comments_count: id3_data.comments.len(),
                        pictures_count: id3_data.pictures.len(),
                        private_frames_count: id3_data.private_frames.len(),
                        suspicious_frames: id3_data.suspicious_frames,
                    });
                }

                // Spectrogram
                if let Ok(spec_data) = SpectrogramAnalyzer::analyze(samples) {
                    audio_analysis.spectrogram_analysis = Some(SpectrogramReport {
                        high_frequency_energy: spec_data.high_frequency_energy,
                        hidden_message_detected: spec_data.has_hidden_message,
                        suspicious_patterns: spec_data.suspicious_patterns,
                    });
                }

                response.format_specific_analysis = FormatSpecificAnalysis::Audio(audio_analysis);
            }
        }
        FileType::Video => {
            if let Ok(frame_iter) = VideoParser::parse_path(&file_path) {
                let mut frame_count = 0;
                let mut error_count = 0;
                let mut suspicious_frames = Vec::new();

                for (idx, frame_result) in frame_iter.enumerate() {
                    match frame_result {
                        Ok(frame) => {
                            frame_count += 1;

                            if idx % video_sample_rate == 0 {
                                let dynamic_image = image::DynamicImage::ImageRgba8(frame);
                                if let Ok(analysis) = VideoFrameAnalyzer::analyze(dynamic_image) {
                                    if analysis.lsb_suspicious || analysis.histogram_anomalies {
                                        suspicious_frames.push(idx);
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            error_count += 1;
                        }
                    }
                }

                response.format_specific_analysis = FormatSpecificAnalysis::Video(VideoAnalysis {
                    frames_processed: frame_count,
                    errors_encountered: error_count,
                    suspicious_frames,
                });
            }
        }
        FileType::Text => {
            if let Ok(text_content) = TextParser::parse_path(&file_path) {
                response.format_specific_analysis = FormatSpecificAnalysis::Text(TextAnalysis {
                    file_type: text_content.file_type,
                    line_count: text_content.line_count,
                    word_count: text_content.word_count,
                    character_count: text_content.char_count,
                    size_bytes: text_content.byte_size,
                });
            }
        }
    }

    // Finalize summary
    finalize_summary(&mut response);

    Ok(response)
}

fn finalize_summary(response: &mut AnalysisResponse) {
    let mut indicators = Vec::new();
    let mut steg_detected = false;

    // Check magic bytes
    if let Some(ref magic) = response.magic_bytes_analysis {
        if magic.has_suspicious_data {
            steg_detected = true;
            indicators.push("Suspicious data in file structure".to_string());
        }
        if magic.has_multiple_formats {
            indicators.push("Multiple file formats detected".to_string());
        }
        indicators.extend(magic.suspicious_findings.clone());
    }

    // Check format-specific
    match &response.format_specific_analysis {
        FormatSpecificAnalysis::Image(img) => {
            if let Some(ref lsb) = img.lsb_analysis {
                if lsb.is_suspicious {
                    steg_detected = true;
                    indicators.push("LSB analysis indicates hidden data".to_string());
                }
            }
        }
        FormatSpecificAnalysis::Audio(audio) => {
            if let Some(ref spec) = audio.spectrogram_analysis {
                if spec.hidden_message_detected {
                    steg_detected = true;
                    indicators.push("Spectrogram analysis detected patterns".to_string());
                }
            }
        }
        FormatSpecificAnalysis::Video(video) => {
            if !video.suspicious_frames.is_empty() {
                steg_detected = true;
                indicators.push(format!(
                    "Found {} suspicious video frames",
                    video.suspicious_frames.len()
                ));
            }
        }
        _ => {}
    }

    let confidence = if indicators.len() >= 3 {
        "high"
    } else if indicators.len() >= 1 {
        "medium"
    } else {
        "low"
    };

    let recommendations = if steg_detected {
        vec![
            "Further investigation recommended".to_string(),
            "Consider specialized tools".to_string(),
            "Verify file source".to_string(),
        ]
    } else {
        vec!["No obvious steganography detected".to_string()]
    };

    response.summary = AnalysisSummary {
        steganography_detected: steg_detected,
        confidence_level: confidence.to_string(),
        threat_indicators: indicators,
        recommendations,
    };
}
