use crate::Parser;
use std::fmt::Display;
use std::fs;
use std::io::Read;
use std::path::Path;

pub struct TextParser;

#[derive(Debug)]
pub enum TextParserError {
    IO(std::io::Error),
    Pdf(String),
    Docx(String),
    Unsupported(String),
}

impl Display for TextParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TextParserError::IO(e) => write!(f, "IO error: {}", e),
            TextParserError::Pdf(e) => write!(f, "PDF parsing error: {}", e),
            TextParserError::Docx(e) => write!(f, "DOCX parsing error: {}", e),
            TextParserError::Unsupported(e) => write!(f, "Unsupported format: {}", e),
        }
    }
}

impl std::error::Error for TextParserError {}

impl From<std::io::Error> for TextParserError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

#[derive(Debug, Clone)]
pub struct TextContent {
    pub content: String,
    pub byte_size: usize,
    pub line_count: usize,
    pub char_count: usize,
    pub word_count: usize,
    pub file_type: String,
}

impl TextContent {
    pub fn new(content: String, file_type: String) -> Self {
        let byte_size = content.len();
        let line_count = content.lines().count();
        let char_count = content.chars().count();
        let word_count = content.split_whitespace().count();

        Self {
            content,
            byte_size,
            line_count,
            char_count,
            word_count,
            file_type,
        }
    }

    pub fn lines(&self) -> impl Iterator<Item = &str> {
        self.content.lines()
    }

    pub fn words(&self) -> impl Iterator<Item = &str> {
        self.content.split_whitespace()
    }
}

impl Parser for TextParser {
    type Output = TextContent;
    type Error = TextParserError;

    fn parse_path<P>(file_path: &P) -> Result<Self::Output, Self::Error>
    where
        P: AsRef<Path>,
    {
        let path = file_path.as_ref();
        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_lowercase();

        match extension.as_str() {
            "pdf" => parse_pdf(path),
            "docx" => parse_docx(path),
            "doc" => parse_doc(path),
            "rtf" => parse_rtf(path),
            "odt" => parse_odt(path),
            _ => parse_plain_text(path, &extension),
        }
    }
}

fn parse_pdf(path: &Path) -> Result<TextContent, TextParserError> {
    use pdf_extract::extract_text;

    match extract_text(path) {
        Ok(text) => Ok(TextContent::new(text, "PDF".to_string())),
        Err(e) => Err(TextParserError::Pdf(format!("{:?}", e))),
    }
}

fn parse_docx(path: &Path) -> Result<TextContent, TextParserError> {
    use docx_rs::read_docx;

    let bytes = fs::read(path)?;

    match read_docx(&bytes) {
        Ok(docx) => {
            let mut text = String::new();

            // Extract text from paragraphs
            for child in docx.document.children {
                if let docx_rs::DocumentChild::Paragraph(para) = child {
                    for child in para.children {
                        if let docx_rs::ParagraphChild::Run(run) = child {
                            for child in run.children {
                                if let docx_rs::RunChild::Text(t) = child {
                                    text.push_str(&t.text);
                                }
                            }
                        }
                    }
                    text.push('\n');
                }
            }

            Ok(TextContent::new(text, "DOCX".to_string()))
        }
        Err(e) => Err(TextParserError::Docx(format!("{:?}", e))),
    }
}

fn parse_doc(path: &Path) -> Result<TextContent, TextParserError> {
    // .doc files (old Word format) are complex binary format
    // Try to extract as much readable text as possible
    let bytes = fs::read(path)?;

    // Try to extract ASCII/UTF-8 strings from binary
    let text = extract_strings_from_binary(&bytes);

    if text.is_empty() {
        Err(TextParserError::Unsupported(
            "Legacy .doc format requires external tool (antiword/catdoc)".to_string(),
        ))
    } else {
        Ok(TextContent::new(text, "DOC (partial)".to_string()))
    }
}

fn parse_rtf(path: &Path) -> Result<TextContent, TextParserError> {
    let bytes = fs::read(path)?;
    let content = String::from_utf8_lossy(&bytes);

    // Option 1: Use rtf-parser crate (if you add it back to Cargo.toml)
    // use rtf_parser::{Lexer, Token};
    // let mut text = String::new();
    // let lexer = Lexer::new(&content);
    // for token in lexer {
    //     if let Token::Text(s) = token {
    //         text.push_str(s);
    //     }
    // }

    // Option 2: Custom RTF text extraction (currently used)
    let text = extract_rtf_plain_text(&content);

    if text.trim().is_empty() {
        Err(TextParserError::Unsupported(
            "No text found in RTF file".to_string(),
        ))
    } else {
        Ok(TextContent::new(text, "RTF".to_string()))
    }
}

fn extract_rtf_plain_text(rtf_content: &str) -> String {
    let mut result = String::new();
    let mut in_control_word = false;
    let mut in_hex = false;
    let mut brace_depth = 0;
    let mut skip_group = false;
    let mut chars = rtf_content.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '{' => {
                brace_depth += 1;
                // Check if this is a group to skip (like \fonttbl, \colortbl, etc.)
                let ahead: String = chars.clone().take(10).collect();
                if ahead.starts_with("\\fonttbl")
                    || ahead.starts_with("\\colortbl")
                    || ahead.starts_with("\\stylesheet")
                    || ahead.starts_with("\\info")
                {
                    skip_group = true;
                }
            }
            '}' => {
                brace_depth -= 1;
                if brace_depth == 0 {
                    skip_group = false;
                }
                in_control_word = false;
            }
            '\\' => {
                if skip_group {
                    continue;
                }

                in_control_word = true;

                // Check for special control sequences
                if let Some(&next_ch) = chars.peek() {
                    match next_ch {
                        '\\' | '{' | '}' => {
                            result.push(next_ch);
                            chars.next();
                            in_control_word = false;
                        }
                        '\'' => {
                            // Hex encoded character
                            chars.next(); // skip '
                            in_hex = true;
                            in_control_word = false;
                        }
                        _ => {}
                    }
                }
            }
            ' ' | '\n' | '\r' if in_control_word => {
                in_control_word = false;
            }
            _ if in_hex => {
                // Skip hex characters
                if ch.is_ascii_hexdigit() {
                    if let Some(&next) = chars.peek() {
                        if next.is_ascii_hexdigit() {
                            chars.next();
                        }
                    }
                }
                in_hex = false;
            }
            _ if !in_control_word && !skip_group && brace_depth > 0 => {
                // Regular text character
                if ch.is_ascii() || ch as u32 > 127 {
                    result.push(ch);
                }
            }
            _ => {}
        }
    }

    result
}

fn parse_odt(path: &Path) -> Result<TextContent, TextParserError> {
    use quick_xml::Reader;
    use quick_xml::events::Event;
    use zip::ZipArchive;

    let file = fs::File::open(path)?;
    let mut archive = ZipArchive::new(file)
        .map_err(|e| TextParserError::Unsupported(format!("Not a valid ODT file: {}", e)))?;

    // ODT files are ZIP archives with content.xml
    let mut content_xml = archive
        .by_name("content.xml")
        .map_err(|e| TextParserError::Unsupported(format!("Missing content.xml: {}", e)))?;

    let mut xml_content = String::new();
    content_xml.read_to_string(&mut xml_content)?;

    // Extract text from XML
    let mut reader = Reader::from_str(&xml_content);
    reader.config_mut().trim_text(true);

    let mut text = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Text(e)) => {
                let txt = e.into_inner();
                if let Ok(decoded) = String::from_utf8(txt.to_vec()) {
                    text.push_str(&decoded);
                    text.push(' ');
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(TextParserError::Unsupported(format!(
                    "XML parse error: {}",
                    e
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(TextContent::new(text, "ODT".to_string()))
}

fn parse_plain_text(path: &Path, extension: &str) -> Result<TextContent, TextParserError> {
    // First try UTF-8
    if let Ok(content) = fs::read_to_string(path) {
        return Ok(TextContent::new(content, extension.to_uppercase()));
    }

    // If that fails, try to detect encoding and convert
    let bytes = fs::read(path)?;

    // Try common encodings
    let encodings = [
        encoding_rs::UTF_8,
        encoding_rs::UTF_16LE,
        encoding_rs::UTF_16BE,
        encoding_rs::WINDOWS_1252,
        encoding_rs::ISO_8859_2,
        encoding_rs::SHIFT_JIS,
        encoding_rs::GB18030,
    ];

    for encoding in &encodings {
        let (decoded, _, had_errors) = encoding.decode(&bytes);
        if !had_errors {
            return Ok(TextContent::new(
                decoded.to_string(),
                extension.to_uppercase(),
            ));
        }
    }

    // Last resort: extract readable strings from binary
    let text = extract_strings_from_binary(&bytes);

    if text.trim().is_empty() {
        Err(TextParserError::Unsupported(
            "Could not decode text with any known encoding".to_string(),
        ))
    } else {
        Ok(TextContent::new(
            text,
            format!("{} (binary extract)", extension.to_uppercase()),
        ))
    }
}

fn extract_strings_from_binary(bytes: &[u8]) -> String {
    let mut result = String::new();
    let mut current = String::new();

    for &byte in bytes {
        if byte >= 32 && byte <= 126 || byte == b'\n' || byte == b'\r' || byte == b'\t' {
            current.push(byte as char);
        } else if byte >= 128 {
            // Might be UTF-8
            current.push(byte as char);
        } else {
            if current.len() > 3 {
                result.push_str(&current);
                result.push(' ');
            }
            current.clear();
        }
    }

    if current.len() > 3 {
        result.push_str(&current);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_simple_text() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "Hello World").unwrap();
        writeln!(file, "This is a test").unwrap();

        let result = TextParser::parse_path(&file.path()).unwrap();
        assert_eq!(result.line_count, 2);
        assert_eq!(result.word_count, 6);
        assert!(result.content.contains("Hello World"));
    }

    #[test]
    fn test_text_content_stats() {
        let content = TextContent::new("Hello World\nTest".to_string(), "TXT".to_string());
        assert_eq!(content.line_count, 2);
        assert_eq!(content.word_count, 3);
        assert_eq!(content.char_count, 16);
    }
}
