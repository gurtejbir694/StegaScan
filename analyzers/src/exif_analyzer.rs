use crate::Analyzer;
use std::collections::HashMap;
use std::fmt::Display;
use std::path::Path;

pub struct ExifAnalyzer;

#[derive(Debug)]
pub enum ExifAnalyzerError {
    IO(std::io::Error),
    ExifError(String),
}

impl Display for ExifAnalyzerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExifAnalyzerError::IO(e) => write!(f, "IO error: {}", e),
            ExifAnalyzerError::ExifError(e) => write!(f, "EXIF parsing error: {}", e),
        }
    }
}

impl std::error::Error for ExifAnalyzerError {}

impl From<std::io::Error> for ExifAnalyzerError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

#[derive(Debug, Clone)]
pub struct ExifData {
    pub metadata: HashMap<String, String>,
    pub has_thumbnail: bool,
    pub thumbnail_size: Option<usize>,
    pub suspicious_fields: Vec<String>,
    pub comment_fields: Vec<String>,
}

impl ExifData {
    pub fn new() -> Self {
        Self {
            metadata: HashMap::new(),
            has_thumbnail: false,
            thumbnail_size: None,
            suspicious_fields: Vec::new(),
            comment_fields: Vec::new(),
        }
    }
}

impl Default for ExifData {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ExifAnalyzerWithPath<'a> {
    path: &'a Path,
}

impl<'a> ExifAnalyzerWithPath<'a> {
    pub fn new(path: &'a Path) -> Self {
        Self { path }
    }

    pub fn analyze(&self) -> Result<ExifData, ExifAnalyzerError> {
        use exif::{In, Reader, Tag};

        let file = std::fs::File::open(self.path)?;
        let mut bufreader = std::io::BufReader::new(&file);

        let exifreader = Reader::new();
        let exif = match exifreader.read_from_container(&mut bufreader) {
            Ok(exif) => exif,
            Err(e) => return Err(ExifAnalyzerError::ExifError(format!("{:?}", e))),
        };

        let mut exif_data = ExifData::new();

        // Extract all EXIF fields
        for field in exif.fields() {
            let tag_name = format!("{}", field.tag);
            let value = field.display_value().to_string();

            exif_data.metadata.insert(tag_name.clone(), value.clone());

            // Check for comment/description fields that could hide data
            match field.tag {
                Tag::UserComment | Tag::ImageDescription => {
                    exif_data
                        .comment_fields
                        .push(format!("{}: {}", tag_name, value));
                }
                _ => {}
            }

            // Check for suspicious patterns
            if value.len() > 1000 {
                exif_data.suspicious_fields.push(format!(
                    "{}: unusually large ({}+ bytes)",
                    tag_name,
                    value.len()
                ));
            }

            // Check for base64-like patterns
            if is_potential_base64(&value) && value.len() > 50 {
                exif_data
                    .suspicious_fields
                    .push(format!("{}: potential encoded data", tag_name));
            }
        }

        // Check for thumbnail
        if let Some(_thumbnail) = exif.get_field(Tag::JPEGInterchangeFormat, In::PRIMARY) {
            exif_data.has_thumbnail = true;
            if let Some(size_field) = exif.get_field(Tag::JPEGInterchangeFormatLength, In::PRIMARY)
            {
                if let Some(size) = size_field.value.get_uint(0) {
                    exif_data.thumbnail_size = Some(size as usize);
                }
            }
        }

        Ok(exif_data)
    }
}

// Placeholder analyzer trait implementation (requires path, not just image data)
impl Analyzer for ExifAnalyzer {
    type Input = (); // Not used, use ExifAnalyzerWithPath instead
    type Output = ExifData;
    type Error = ExifAnalyzerError;

    fn analyze(_input: Self::Input) -> Result<Self::Output, Self::Error> {
        // This is a placeholder - use ExifAnalyzerWithPath::new(path).analyze() instead
        Ok(ExifData::new())
    }
}

fn is_potential_base64(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }

    let base64_chars = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();

    // If more than 90% of characters are valid base64, might be encoded
    (base64_chars as f64 / s.len() as f64) > 0.9
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_detection() {
        assert!(is_potential_base64("SGVsbG8gV29ybGQ="));
        assert!(is_potential_base64("dGVzdGluZzEyMzQ1Njc4OTA="));
        assert!(!is_potential_base64("Hello World"));
        assert!(!is_potential_base64("abc"));
    }
}
