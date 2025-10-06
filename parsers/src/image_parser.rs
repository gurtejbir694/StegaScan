use std::fmt::Display;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path};

use crate::Parser;

pub struct ImageParser;

#[derive(Debug)]
pub enum ImageParserError {
    IO(std::io::Error),
    Parse(image::error::ImageError),
}

impl Display for ImageParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

impl From<std::io::Error> for ImageParserError {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value)
    }
}

impl From<image::error::ImageError> for ImageParserError {
    fn from(value: image::error::ImageError) -> Self {
        Self::Parse(value)
    }
}

impl Parser for ImageParser {
    type Output = image::DynamicImage;

    type Error = ImageParserError;

    fn parse_path<P>(file_path: &P) -> Result<Self::Output, Self::Error>
    where
        P: AsRef<Path>,
    {
        let file = File::open(file_path)?;
        Ok(image::load(
            BufReader::new(file),
            image::ImageFormat::from_path(file_path)?,
        )?)
    }
}
