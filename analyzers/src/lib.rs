pub mod exif_analyzer;
pub mod id3_analyzer;
pub mod image_filter;
pub mod lsb_analyzer;
pub mod magic_bytes_analyzer;
pub mod spectrogram_analyzer;
pub trait Analyzer {
    type Output;
    type Input;
    type Error;

    fn analyze(input: Self::Input) -> Result<Self::Output, Self::Error>;
}
