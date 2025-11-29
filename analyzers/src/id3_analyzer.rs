use crate::Analyzer;
use std::collections::HashMap;
use std::fmt::Display;
use std::path::Path;

pub struct Id3Analyzer;

#[derive(Debug)]
pub enum Id3AnalyzerError {
    IO(std::io::Error),
    Id3Error(String),
}

impl Display for Id3AnalyzerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Id3AnalyzerError::IO(e) => write!(f, "IO error: {}", e),
            Id3AnalyzerError::Id3Error(e) => write!(f, "ID3 parsing error: {}", e),
        }
    }
}

impl std::error::Error for Id3AnalyzerError {}

impl From<std::io::Error> for Id3AnalyzerError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

#[derive(Debug, Clone)]
pub struct Id3Data {
    pub title: Option<String>,
    pub artist: Option<String>,
    pub album: Option<String>,
    pub year: Option<i32>,
    pub comments: Vec<String>,
    pub lyrics: Option<String>,
    pub all_frames: HashMap<String, String>,
    pub suspicious_frames: Vec<String>,
    pub pictures: Vec<PictureInfo>,
    pub private_frames: Vec<PrivateFrame>,
}

#[derive(Debug, Clone)]
pub struct PictureInfo {
    pub picture_type: String,
    pub mime_type: String,
    pub description: String,
    pub data_size: usize,
}

#[derive(Debug, Clone)]
pub struct PrivateFrame {
    pub owner: String,
    pub data_size: usize,
    pub is_binary: bool,
}

impl Id3Data {
    pub fn new() -> Self {
        Self {
            title: None,
            artist: None,
            album: None,
            year: None,
            comments: Vec::new(),
            lyrics: None,
            all_frames: HashMap::new(),
            suspicious_frames: Vec::new(),
            pictures: Vec::new(),
            private_frames: Vec::new(),
        }
    }
}

impl Default for Id3Data {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Id3AnalyzerWithPath<'a> {
    path: &'a Path,
}

impl<'a> Id3AnalyzerWithPath<'a> {
    pub fn new(path: &'a Path) -> Self {
        Self { path }
    }

    pub fn analyze(&self) -> Result<Id3Data, Id3AnalyzerError> {
        use id3::{Tag, TagLike};

        let tag = Tag::read_from_path(self.path)
            .map_err(|e| Id3AnalyzerError::Id3Error(format!("{:?}", e)))?;

        let mut id3_data = Id3Data::new();

        // Extract basic metadata
        id3_data.title = tag.title().map(|s| s.to_string());
        id3_data.artist = tag.artist().map(|s| s.to_string());
        id3_data.album = tag.album().map(|s| s.to_string());
        id3_data.year = tag.year();

        // Extract comments
        for comment in tag.comments() {
            let comment_text = format!(
                "{} [{}]: {}",
                comment.lang, comment.description, comment.text
            );
            id3_data.comments.push(comment_text.clone());

            // Check for suspicious patterns in comments
            if comment.text.len() > 500 {
                id3_data
                    .suspicious_frames
                    .push(format!("Large comment field: {} bytes", comment.text.len()));
            }

            if is_potential_base64(&comment.text) && comment.text.len() > 50 {
                id3_data
                    .suspicious_frames
                    .push(format!("Comment contains potential encoded data"));
            }
        }

        // Extract lyrics
        if let Some(lyrics) = tag.lyrics().next() {
            id3_data.lyrics = Some(lyrics.text.clone());

            if lyrics.text.len() > 10000 {
                id3_data.suspicious_frames.push(format!(
                    "Unusually large lyrics: {} bytes",
                    lyrics.text.len()
                ));
            }
        }

        // Extract pictures (APIC frames)
        for picture in tag.pictures() {
            let pic_info = PictureInfo {
                picture_type: format!("{:?}", picture.picture_type),
                mime_type: picture.mime_type.clone(),
                description: picture.description.clone(),
                data_size: picture.data.len(),
            };

            // Check for suspicious picture sizes
            if picture.data.len() > 5_000_000 {
                id3_data.suspicious_frames.push(format!(
                    "Large embedded picture: {} MB",
                    picture.data.len() / 1_000_000
                ));
            }

            id3_data.pictures.push(pic_info);
        }

        // Extract private frames (PRIV)
        for frame in tag.frames() {
            if frame.id() == "PRIV" {
                // Get raw content for private frames
                let content_str = format!("{:?}", frame.content());
                let content_len = content_str.len();

                if content_len > 1000 {
                    id3_data
                        .suspicious_frames
                        .push(format!("Large private frame: ~{} bytes", content_len));
                }

                let priv_info = PrivateFrame {
                    owner: "PRIV".to_string(),
                    data_size: content_len,
                    is_binary: true,
                };

                id3_data.private_frames.push(priv_info);
            }

            // Store all frames
            let frame_id = frame.id().to_string();
            let frame_value = format!("{:?}", frame.content());
            id3_data.all_frames.insert(frame_id, frame_value);
        }

        Ok(id3_data)
    }
}

// Placeholder analyzer trait implementation (requires path, not just audio data)
impl Analyzer for Id3Analyzer {
    type Input = (); // Not used, use Id3AnalyzerWithPath instead
    type Output = Id3Data;
    type Error = Id3AnalyzerError;

    fn analyze(_input: Self::Input) -> Result<Self::Output, Self::Error> {
        // This is a placeholder - use Id3AnalyzerWithPath::new(path).analyze() instead
        Ok(Id3Data::new())
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
