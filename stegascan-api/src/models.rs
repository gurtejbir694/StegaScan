use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResponse {
    pub file_info: FileInfo,
    pub magic_bytes_analysis: Option<MagicBytesReport>,
    pub format_specific_analysis: FormatSpecificAnalysis,
    pub timestamp: String,
    pub summary: AnalysisSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub size_bytes: u64,
    pub detected_type: String,
    pub extension: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatSummary {
    pub images: usize,
    pub audio: usize,
    pub video: usize,
    pub text_documents: usize,
    pub archives: usize,
    pub executables: usize,
    pub other: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedFileInfo {
    pub offset: usize,
    pub offset_hex: String,
    pub description: String,
    pub file_type: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FormatSpecificAnalysis {
    Image(ImageAnalysis),
    Audio(AudioAnalysis),
    Video(VideoAnalysis),
    Text(TextAnalysis),
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageAnalysis {
    pub exif_metadata: Option<ExifReport>,
    pub lsb_analysis: Option<LsbReport>,
    pub dimensions: ImageDimensions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageDimensions {
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExifReport {
    pub fields_found: usize,
    pub has_thumbnail: bool,
    pub thumbnail_size_bytes: Option<usize>,
    pub comment_fields: Vec<String>,
    pub suspicious_fields: Vec<String>,
    pub metadata: Vec<MetadataField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataField {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsbReport {
    pub is_suspicious: bool,
    pub channels: Vec<LsbChannelAnalysis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsbChannelAnalysis {
    pub channel_name: String,
    pub chi_square_score: f64,
    pub entropy_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioAnalysis {
    pub sample_count: usize,
    pub id3_analysis: Option<Id3Report>,
    pub spectrogram_analysis: Option<SpectrogramReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpectrogramReport {
    pub high_frequency_energy: f64,
    pub hidden_message_detected: bool,
    pub suspicious_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoAnalysis {
    pub frames_processed: usize,
    pub errors_encountered: usize,
    pub suspicious_frames: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextAnalysis {
    pub file_type: String,
    pub line_count: usize,
    pub word_count: usize,
    pub character_count: usize,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub steganography_detected: bool,
    pub confidence_level: String,
    pub threat_indicators: Vec<String>,
    pub recommendations: Vec<String>,
}
