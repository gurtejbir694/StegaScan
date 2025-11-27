pub mod audio_parser;
pub mod image_parser;
pub mod video_parser;
use std::path::Path;

pub trait Parser {
    type Output;
    type Error;

    fn parse_path<P: AsRef<Path>>(file_path: &P) -> Result<Self::Output, Self::Error>;
}
