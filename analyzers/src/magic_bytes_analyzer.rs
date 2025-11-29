use crate::Analyzer;
use binwalk::Binwalk;
use std::fmt::Display;
use std::path::Path;

pub struct MagicBytesAnalyzer;

#[derive(Debug)]
pub enum MagicBytesError {
    IO(std::io::Error),
    Analysis(String),
}

impl Display for MagicBytesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MagicBytesError::IO(e) => write!(f, "IO error: {}", e),
            MagicBytesError::Analysis(e) => write!(f, "Analysis error: {}", e),
        }
    }
}

impl std::error::Error for MagicBytesError {}

impl From<std::io::Error> for MagicBytesError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

#[derive(Debug, Clone)]
pub struct MagicBytesAnalysis {
    pub primary_format: String,
    pub expected_format: Option<String>,
    pub total_signatures_found: usize,
    pub embedded_files: Vec<EmbeddedFile>,
    pub has_multiple_formats: bool,
    pub has_suspicious_data: bool,
    pub suspicious_findings: Vec<String>,
    pub format_summary: FormatSummary,
}

#[derive(Debug, Clone)]
pub struct EmbeddedFile {
    pub offset: usize,
    pub description: String,
    pub file_type: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Default)]
pub struct FormatSummary {
    pub audio_files: usize,
    pub video_files: usize,
    pub image_files: usize,
    pub text_files: usize,
    pub archive_files: usize,
    pub executable_files: usize,
    pub other_files: usize,
}

pub struct MagicBytesAnalyzerWithPath<'a> {
    path: &'a Path,
}

impl<'a> MagicBytesAnalyzerWithPath<'a> {
    pub fn new(path: &'a Path) -> Self {
        Self { path }
    }

    pub fn analyze(&self) -> Result<MagicBytesAnalysis, MagicBytesError> {
        use std::fs;

        // Read file data
        let file_data = fs::read(self.path)?;

        if file_data.is_empty() {
            return Err(MagicBytesError::Analysis("Empty file".to_string()));
        }

        // Get expected format from file extension
        let expected_format = self
            .path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_uppercase());

        // Run binwalk analysis
        let binwalk = Binwalk::new();
        let binwalk_results = binwalk.scan(&file_data);

        // Extract signature results from binwalk
        let mut all_results = Vec::new();

        for sig in binwalk_results {
            all_results.push(EmbeddedFile {
                offset: sig.offset,
                description: sig.name.clone(),
                file_type: determine_file_category(&sig.name).to_string(),
                confidence: match sig.confidence {
                    0..100 => "low",
                    100..200 => "medium",
                    200..=u8::MAX => "high",
                }
                .to_string(),
            });
        }

        // Also do our own basic signature detection for common formats binwalk might miss
        let manual_results = manual_signature_scan(&file_data);

        // Merge manual results
        for manual_result in manual_results {
            // Only add if not already found by binwalk at same offset
            if !all_results.iter().any(|r| r.offset == manual_result.offset) {
                all_results.push(manual_result);
            }
        }

        // Sort by offset
        all_results.sort_by_key(|r| r.offset);

        // Process results
        let mut format_summary = FormatSummary::default();
        let mut suspicious_findings = Vec::new();

        // Determine primary format (usually at offset 0)
        let primary_format = if let Some(first_result) = all_results.first() {
            if first_result.offset == 0 {
                categorize_file_type(&first_result.description, &mut format_summary);
                first_result.description.clone()
            } else {
                // Check file start manually if binwalk didn't find it
                detect_format_at_offset(&file_data, 0)
            }
        } else {
            // No results from binwalk, detect manually
            detect_format_at_offset(&file_data, 0)
        };

        // Process all signatures found
        for result in &all_results {
            // Categorize for summary (only once per signature)
            categorize_file_type(&result.description, &mut format_summary);

            // Check for suspicious patterns
            if result.offset > 0 {
                // Data found after offset 0 could be hidden
                if is_complete_file_signature(&result.description) {
                    suspicious_findings.push(format!(
                        "Complete file signature found at offset 0x{:X}: {}",
                        result.offset, result.description
                    ));
                }
            }
        }

        // Adjust format summary - primary format was already counted, remove the duplicate
        if !all_results.is_empty() && all_results[0].offset == 0 {
            // The primary format was counted, but we don't want to double-count it
            let first_type = determine_file_category(&all_results[0].description);
            match first_type {
                "Image" => {
                    format_summary.image_files = format_summary.image_files.saturating_sub(1)
                }
                "Audio" => {
                    format_summary.audio_files = format_summary.audio_files.saturating_sub(1)
                }
                "Video" => {
                    format_summary.video_files = format_summary.video_files.saturating_sub(1)
                }
                "Text/Document" => {
                    format_summary.text_files = format_summary.text_files.saturating_sub(1)
                }
                "Archive" => {
                    format_summary.archive_files = format_summary.archive_files.saturating_sub(1)
                }
                "Executable" => {
                    format_summary.executable_files =
                        format_summary.executable_files.saturating_sub(1)
                }
                _ => format_summary.other_files = format_summary.other_files.saturating_sub(1),
            }
        }

        // Check if file extension matches detected format
        if let Some(expected) = &expected_format {
            let primary_upper = primary_format.to_uppercase();
            if !primary_upper.contains(expected.as_str()) && primary_format != "UNKNOWN" {
                suspicious_findings.push(format!(
                    "Format mismatch: extension says {}, detected format is {}",
                    expected, primary_format
                ));
            }
        }

        // Determine if multiple formats exist
        let has_multiple_formats = all_results.len() > 1;

        if has_multiple_formats {
            suspicious_findings.push(format!(
                "Multiple file signatures detected ({} total)",
                all_results.len()
            ));
        }

        // Check for polyglot files (audio + video + image + text)
        let is_polyglot = format_summary.audio_files > 0
            && format_summary.image_files > 0
            && (format_summary.video_files > 0 || format_summary.text_files > 0);

        if is_polyglot {
            suspicious_findings.push(
                "POLYGLOT FILE DETECTED: Contains multiple media types (possible steganography)"
                    .to_string(),
            );
        }

        // Check for data in unusual locations
        let has_suspicious_data = all_results
            .iter()
            .any(|r| r.offset > 0 && is_complete_file_signature(&r.description));

        // Summary of findings
        let total_signatures_found = all_results.len();

        Ok(MagicBytesAnalysis {
            primary_format,
            expected_format,
            total_signatures_found,
            embedded_files: all_results,
            has_multiple_formats,
            has_suspicious_data,
            suspicious_findings,
            format_summary,
        })
    }
}

// Placeholder analyzer trait implementation
impl Analyzer for MagicBytesAnalyzer {
    type Input = ();
    type Output = MagicBytesAnalysis;
    type Error = MagicBytesError;

    fn analyze(_input: Self::Input) -> Result<Self::Output, Self::Error> {
        Err(MagicBytesError::Analysis(
            "Use MagicBytesAnalyzerWithPath::new(path).analyze() instead".to_string(),
        ))
    }
}

fn determine_file_category(description: &str) -> &str {
    let desc_lower = description.to_lowercase();

    if desc_lower.contains("jpeg")
        || desc_lower.contains("png")
        || desc_lower.contains("gif")
        || desc_lower.contains("bmp")
        || desc_lower.contains("tiff")
        || desc_lower.contains("webp")
        || desc_lower.contains("image")
    {
        "Image"
    } else if desc_lower.contains("mp3")
        || desc_lower.contains("wav")
        || desc_lower.contains("flac")
        || desc_lower.contains("ogg")
        || desc_lower.contains("aac")
        || desc_lower.contains("audio")
    {
        "Audio"
    } else if desc_lower.contains("mp4")
        || desc_lower.contains("avi")
        || desc_lower.contains("mkv")
        || desc_lower.contains("webm")
        || desc_lower.contains("mov")
        || desc_lower.contains("video")
    {
        "Video"
    } else if desc_lower.contains("pdf")
        || desc_lower.contains("doc")
        || desc_lower.contains("txt")
        || desc_lower.contains("rtf")
        || desc_lower.contains("xml")
        || desc_lower.contains("html")
    {
        "Text/Document"
    } else if desc_lower.contains("zip")
        || desc_lower.contains("rar")
        || desc_lower.contains("tar")
        || desc_lower.contains("7z")
        || desc_lower.contains("gzip")
        || desc_lower.contains("archive")
    {
        "Archive"
    } else if desc_lower.contains("exe")
        || desc_lower.contains("elf")
        || desc_lower.contains("mach-o")
        || desc_lower.contains("executable")
    {
        "Executable"
    } else {
        "Other"
    }
}

fn categorize_file_type(description: &str, summary: &mut FormatSummary) {
    match determine_file_category(description) {
        "Image" => summary.image_files += 1,
        "Audio" => summary.audio_files += 1,
        "Video" => summary.video_files += 1,
        "Text/Document" => summary.text_files += 1,
        "Archive" => summary.archive_files += 1,
        "Executable" => summary.executable_files += 1,
        _ => summary.other_files += 1,
    }
}

fn is_complete_file_signature(description: &str) -> bool {
    let desc_lower = description.to_lowercase();

    // These indicate a complete file header, not just a fragment
    desc_lower.contains("header")
        || desc_lower.contains("jpeg image")
        || desc_lower.contains("png image")
        || desc_lower.contains("gif image")
        || desc_lower.contains("pdf document")
        || desc_lower.contains("zip archive")
        || desc_lower.contains("rar archive")
        || desc_lower.contains("audio")
        || desc_lower.contains("video")
}

// Manual signature detection for formats binwalk might miss
// This is more conservative to avoid false positives from compressed data
fn manual_signature_scan(data: &[u8]) -> Vec<EmbeddedFile> {
    let mut results = Vec::new();

    // Only search for complete file headers at reasonable boundaries
    // Skip short signatures that could be random data (like 0xFF 0xFB for MP3)
    let signatures: Vec<(Vec<u8>, &str, bool)> = vec![
        // Audio (only look for complete headers)
        (vec![0x52, 0x49, 0x46, 0x46], "RIFF container", true), // Need to verify WAVE header
        (vec![0x49, 0x44, 0x33], "ID3 tag", true),              // Too short, skip
        (vec![0x66, 0x4C, 0x61, 0x43], "FLAC audio", true),
        (vec![0x4F, 0x67, 0x67, 0x53], "OGG audio", true),
        // Images (complete headers only)
        (vec![0xFF, 0xD8, 0xFF, 0xE0], "JPEG image (JFIF)", true),
        (vec![0xFF, 0xD8, 0xFF, 0xE1], "JPEG image (Exif)", true),
        (
            vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
            "PNG image",
            true,
        ),
        (
            vec![0x47, 0x49, 0x46, 0x38, 0x37, 0x61],
            "GIF87a image",
            true,
        ),
        (
            vec![0x47, 0x49, 0x46, 0x38, 0x39, 0x61],
            "GIF89a image",
            true,
        ),
        // Documents
        (vec![0x25, 0x50, 0x44, 0x46, 0x2D], "PDF document", true),
        (vec![0x50, 0x4B, 0x03, 0x04], "ZIP archive", true),
        // Archives (complete headers)
        (
            vec![0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],
            "RAR archive",
            true,
        ),
        (
            vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
            "7-Zip archive",
            true,
        ),
        (vec![0x1A, 0x45, 0xDF, 0xA3], "Webm/mkv", true),
        (vec![0x66, 0x74, 0x79, 0x70], "Mp4", true),
    ];

    // Search for signatures, but be smart about it
    for (signature, description, should_scan) in &signatures {
        if !should_scan {
            continue; // Skip signatures prone to false positives
        }

        let mut pos = 0;
        while pos <= data.len().saturating_sub(signature.len()) {
            if data[pos..].starts_with(signature) {
                // Additional validation for RIFF containers
                if description.contains("RIFF") {
                    if pos + 12 <= data.len() {
                        let riff_type = &data[pos + 8..pos + 12];
                        if riff_type == b"WAVE" {
                            results.push(EmbeddedFile {
                                offset: pos,
                                description: "WAV audio (RIFF/WAVE)".to_string(),
                                file_type: "Audio".to_string(),
                                confidence: "high".to_string(),
                            });
                        } else if riff_type == b"AVI " {
                            results.push(EmbeddedFile {
                                offset: pos,
                                description: "AVI video (RIFF)".to_string(),
                                file_type: "Video".to_string(),
                                confidence: "high".to_string(),
                            });
                        } else if riff_type == b"WEBP" {
                            results.push(EmbeddedFile {
                                offset: pos,
                                description: "WebP image (RIFF)".to_string(),
                                file_type: "Image".to_string(),
                                confidence: "high".to_string(),
                            });
                        }
                    }
                } else {
                    // For other signatures, only report if at a reasonable offset
                    // Skip if it's in the middle of compressed data (likely false positive)
                    if pos == 0 || is_likely_real_file(data, pos, signature.len()) {
                        results.push(EmbeddedFile {
                            offset: pos,
                            description: description.to_string(),
                            file_type: determine_file_category(description).to_string(),
                            confidence: "medium".to_string(),
                        });
                    }
                }
                pos += signature.len();
            } else {
                pos += 1;
            }
        }
    }

    results
}

// Check if a signature at this offset is likely a real file, not random compressed data
fn is_likely_real_file(data: &[u8], offset: usize, _sig_len: usize) -> bool {
    // If it's at the very start, it's likely real
    if offset == 0 {
        return true;
    }

    // Check if the data before this offset looks like padding or alignment
    // Real embedded files are often aligned or have recognizable patterns before them
    if offset >= 4 {
        let before = &data[offset.saturating_sub(4)..offset];
        // Check for common padding patterns
        if before.iter().all(|&b| b == 0x00) {
            return true; // Null padding before file
        }
        if before.iter().all(|&b| b == 0xFF) {
            return true; // xFF padding
        }
    }

    // Check if offset is aligned to common boundaries (512, 1024, 2048, 4096 bytes)
    // Real embedded files are often sector-aligned
    if offset % 512 == 0 || offset % 1024 == 0 {
        return true;
    }

    // Otherwise, it's probably random data in compressed content
    false
}

fn detect_format_at_offset(data: &[u8], offset: usize) -> String {
    if offset >= data.len() || data.len() < offset + 4 {
        return "UNKNOWN".to_string();
    }

    let bytes = &data[offset..];

    // Check common file signatures
    if bytes.starts_with(&[0x52, 0x49, 0x46, 0x46]) {
        if data.len() > offset + 8 {
            match &data[offset + 8..offset + 12] {
                b"WAVE" => return "WAV audio".to_string(),
                b"AVI " => return "AVI video".to_string(),
                b"WEBP" => return "WEBP image".to_string(),
                _ => return "RIFF container".to_string(),
            }
        }
        return "RIFF container".to_string();
    }

    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return "JPEG image".to_string();
    }

    if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        return "PNG image".to_string();
    }

    if bytes.starts_with(&[0x47, 0x49, 0x46, 0x38]) {
        return "GIF image".to_string();
    }

    if bytes.starts_with(&[0x25, 0x50, 0x44, 0x46]) {
        return "PDF document".to_string();
    }

    if bytes.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        return "ZIP archive".to_string();
    }

    if bytes.starts_with(&[0x49, 0x44, 0x33]) {
        return "MP3 audio (with ID3)".to_string();
    }

    if bytes.starts_with(&[0xFF, 0xFB])
        || bytes.starts_with(&[0xFF, 0xF3])
        || bytes.starts_with(&[0xFF, 0xF2])
    {
        return "MP3 audio".to_string();
    }

    if bytes.starts_with(&[0x66, 0x4C, 0x61, 0x43]) {
        return "FLAC audio".to_string();
    }

    "UNKNOWN".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_categorization() {
        assert_eq!(determine_file_category("JPEG image data"), "Image");
        assert_eq!(determine_file_category("PNG image data"), "Image");
        assert_eq!(determine_file_category("MP3 audio"), "Audio");
        assert_eq!(determine_file_category("MP4 video"), "Video");
        assert_eq!(determine_file_category("PDF document"), "Text/Document");
        assert_eq!(determine_file_category("ZIP archive"), "Archive");
    }

    #[test]
    fn test_complete_signature_detection() {
        assert!(is_complete_file_signature("JPEG image data"));
        assert!(is_complete_file_signature("PNG image header"));
        assert!(is_complete_file_signature("PDF document"));
        assert!(!is_complete_file_signature("random data"));
    }
}
