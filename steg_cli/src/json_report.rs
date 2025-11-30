use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug)]
pub struct SteganalysisReport {
    pub file_info: FileInfo,
    pub magic_bytes_analysis: Option<MagicBytesReport>,
    pub format_specific_analysis: FormatSpecificAnalysis,
    pub timestamp: String,
    pub summary: AnalysisSummary,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FileInfo {
    pub path: String,
    pub size_bytes: u64,
    pub detected_type: String,
    pub extension: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MagicBytesReport {
    pub primary_format: String,
    pub expected_format: Option<String>,
    pub total_signatures_found: usize,
    pub has_multiple_formats: bool,
    pub has_suspicious_data: bool,
    pub format_summary: FormatSummary,
    pub embedded_files: Vec<EmbeddedFileInfo>,
    pub suspicious_findings: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FormatSummary {
    pub images: usize,
    pub audio: usize,
    pub video: usize,
    pub text_documents: usize,
    pub archives: usize,
    pub executables: usize,
    pub other: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EmbeddedFileInfo {
    pub offset: usize,
    pub offset_hex: String,
    pub description: String,
    pub file_type: String,
    pub confidence: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum FormatSpecificAnalysis {
    Image(ImageAnalysis),
    Audio(AudioAnalysis),
    Video(VideoAnalysis),
    Text(TextAnalysis),
    Unknown,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ImageAnalysis {
    pub exif_metadata: Option<ExifReport>,
    pub lsb_analysis: Option<LsbReport>,
    pub filter_analysis: FilterAnalysisReport,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExifReport {
    pub fields_found: usize,
    pub has_thumbnail: bool,
    pub thumbnail_size_bytes: Option<usize>,
    pub comment_fields: Vec<String>,
    pub suspicious_fields: Vec<String>,
    pub metadata: Vec<MetadataField>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MetadataField {
    pub key: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LsbReport {
    pub is_suspicious: bool,
    pub channels: Vec<LsbChannelAnalysis>,
    pub output_files: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LsbChannelAnalysis {
    pub channel_name: String,
    pub chi_square_score: f64,
    pub entropy_score: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FilterAnalysisReport {
    pub filters_generated: usize,
    pub output_files: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AudioAnalysis {
    pub sample_count: usize,
    pub id3_analysis: Option<Id3Report>,
    pub spectrogram_analysis: Option<SpectrogramReport>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Id3Report {
    pub title: Option<String>,
    pub artist: Option<String>,
    pub album: Option<String>,
    pub year: Option<i32>,
    pub comments_count: usize,
    pub pictures_count: usize,
    pub private_frames_count: usize,
    pub suspicious_frames: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SpectrogramReport {
    pub high_frequency_energy: f64,
    pub hidden_message_detected: bool,
    pub suspicious_patterns: Vec<String>,
    pub output_file: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VideoAnalysis {
    pub frames_processed: usize,
    pub errors_encountered: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TextAnalysis {
    pub file_type: String,
    pub line_count: usize,
    pub word_count: usize,
    pub character_count: usize,
    pub size_bytes: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AnalysisSummary {
    pub steganography_detected: bool,
    pub confidence_level: String, // "low", "medium", "high"
    pub threat_indicators: Vec<String>,
    pub recommendations: Vec<String>,
}

impl SteganalysisReport {
    pub fn new(file_path: &PathBuf, file_size: u64, detected_type: String) -> Self {
        let extension = file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|s| s.to_string());

        Self {
            file_info: FileInfo {
                path: file_path.to_string_lossy().to_string(),
                size_bytes: file_size,
                detected_type,
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
        }
    }

    pub fn set_magic_bytes_analysis(&mut self, analysis: MagicBytesReport) {
        self.magic_bytes_analysis = Some(analysis);
    }

    pub fn set_format_analysis(&mut self, analysis: FormatSpecificAnalysis) {
        self.format_specific_analysis = analysis;
    }

    pub fn finalize_summary(&mut self) {
        // Determine if steganography was detected
        let mut indicators = Vec::new();
        let mut steg_detected = false;

        // Check magic bytes analysis
        if let Some(ref magic) = self.magic_bytes_analysis {
            if magic.has_suspicious_data {
                steg_detected = true;
                indicators.push("Suspicious data found in file structure".to_string());
            }
            if magic.has_multiple_formats {
                indicators.push("Multiple file formats detected".to_string());
            }
            if !magic.suspicious_findings.is_empty() {
                steg_detected = true;
                indicators.extend(magic.suspicious_findings.clone());
            }
        }

        // Check format-specific analysis
        match &self.format_specific_analysis {
            FormatSpecificAnalysis::Image(img) => {
                if let Some(ref lsb) = img.lsb_analysis {
                    if lsb.is_suspicious {
                        steg_detected = true;
                        indicators.push("LSB analysis indicates possible hidden data".to_string());
                    }
                }
                if let Some(ref exif) = img.exif_metadata {
                    if !exif.suspicious_fields.is_empty() {
                        indicators.push("Suspicious EXIF metadata found".to_string());
                    }
                }
            }
            FormatSpecificAnalysis::Audio(audio) => {
                if let Some(ref spec) = audio.spectrogram_analysis {
                    if spec.hidden_message_detected {
                        steg_detected = true;
                        indicators
                            .push("Spectrogram analysis detected hidden patterns".to_string());
                    }
                }
                if let Some(ref id3) = audio.id3_analysis {
                    if !id3.suspicious_frames.is_empty() {
                        indicators.push("Suspicious ID3 metadata found".to_string());
                    }
                }
            }
            _ => {}
        }

        // Determine confidence level
        let confidence = if indicators.len() >= 3 {
            "high"
        } else if indicators.len() >= 1 {
            "medium"
        } else {
            "low"
        };

        // Generate recommendations
        let mut recommendations = Vec::new();
        if steg_detected {
            recommendations.push("Further investigation recommended".to_string());
            recommendations.push("Consider using specialized steganography tools".to_string());
            recommendations.push("Verify file source and integrity".to_string());
        } else {
            recommendations.push("No obvious steganography detected".to_string());
            recommendations.push("File appears to be clean".to_string());
        }

        self.summary = AnalysisSummary {
            steganography_detected: steg_detected,
            confidence_level: confidence.to_string(),
            threat_indicators: indicators,
            recommendations,
        };
    }

    pub fn save_to_file(&self, output_path: &str) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        let mut file = fs::File::create(output_path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_creation() {
        let path = PathBuf::from("/test/file.png");
        let report = SteganalysisReport::new(&path, 1024, "Image".to_string());

        assert_eq!(report.file_info.size_bytes, 1024);
        assert_eq!(report.file_info.detected_type, "Image");
        assert!(report.magic_bytes_analysis.is_none());
    }

    #[test]
    fn test_json_serialization() {
        let path = PathBuf::from("/test/file.png");
        let report = SteganalysisReport::new(&path, 1024, "Image".to_string());

        let json = report.to_json();
        assert!(json.is_ok());
    }
}
