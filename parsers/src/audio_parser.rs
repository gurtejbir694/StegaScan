use crate::Parser;
use std::fmt::Display;
use std::path::Path;
use symphonia::core::audio::{AudioBufferRef, Signal};
use symphonia::core::codecs::DecoderOptions;
use symphonia::core::formats::FormatOptions;
use symphonia::core::io::MediaSourceStream;
use symphonia::core::meta::MetadataOptions;
use symphonia::core::probe::Hint;

pub struct AudioParser;

#[derive(Debug)]
pub enum AudioParserError {
    IO(std::io::Error),
    Symphonia(String),
    Decode(String),
}

impl Display for AudioParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AudioParserError::IO(e) => write!(f, "IO error: {}", e),
            AudioParserError::Symphonia(e) => write!(f, "Symphonia error: {}", e),
            AudioParserError::Decode(e) => write!(f, "Decode error: {}", e),
        }
    }
}

impl std::error::Error for AudioParserError {}

impl From<std::io::Error> for AudioParserError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl Parser for AudioParser {
    type Output = Vec<f32>;
    type Error = AudioParserError;

    fn parse_path<P>(file_path: &P) -> Result<Self::Output, Self::Error>
    where
        P: AsRef<Path>,
    {
        let file = std::fs::File::open(file_path.as_ref())?;
        let mss = MediaSourceStream::new(Box::new(file), Default::default());

        let mut hint = Hint::new();
        if let Some(extension) = file_path.as_ref().extension() {
            if let Some(ext_str) = extension.to_str() {
                hint.with_extension(ext_str);
            }
        }

        let format_opts = FormatOptions::default();
        let metadata_opts = MetadataOptions::default();
        let decoder_opts = DecoderOptions::default();

        let probed = symphonia::default::get_probe()
            .format(&hint, mss, &format_opts, &metadata_opts)
            .map_err(|e| AudioParserError::Symphonia(format!("{:?}", e)))?;

        let mut format = probed.format;
        let track = format
            .tracks()
            .iter()
            .find(|t| t.codec_params.codec != symphonia::core::codecs::CODEC_TYPE_NULL)
            .ok_or_else(|| AudioParserError::Decode("No audio track found".to_string()))?;

        let mut decoder = symphonia::default::get_codecs()
            .make(&track.codec_params, &decoder_opts)
            .map_err(|e| AudioParserError::Decode(format!("{:?}", e)))?;

        let track_id = track.id;
        let mut samples = Vec::new();

        loop {
            let packet = match format.next_packet() {
                Ok(packet) => packet,
                Err(symphonia::core::errors::Error::IoError(e))
                    if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    break;
                }
                Err(e) => {
                    return Err(AudioParserError::Symphonia(format!("{:?}", e)));
                }
            };

            if packet.track_id() != track_id {
                continue;
            }

            match decoder.decode(&packet) {
                Ok(decoded) => {
                    // Convert various audio buffer types to f32 samples
                    match decoded {
                        AudioBufferRef::U8(buf) => {
                            for &sample in buf.chan(0) {
                                samples.push((sample as f32 - 128.0) / 128.0);
                            }
                        }
                        AudioBufferRef::U16(buf) => {
                            for &sample in buf.chan(0) {
                                samples.push((sample as f32 - 32768.0) / 32768.0);
                            }
                        }
                        AudioBufferRef::U24(buf) => {
                            for &sample in buf.chan(0) {
                                let val = sample.inner() as f32;
                                samples.push((val - 8388608.0) / 8388608.0);
                            }
                        }
                        AudioBufferRef::U32(buf) => {
                            for &sample in buf.chan(0) {
                                samples.push((sample as f64 - 2147483648.0) as f32 / 2147483648.0);
                            }
                        }
                        AudioBufferRef::S8(buf) => {
                            for &sample in buf.chan(0) {
                                samples.push(sample as f32 / 128.0);
                            }
                        }
                        AudioBufferRef::S16(buf) => {
                            for &sample in buf.chan(0) {
                                samples.push(sample as f32 / 32768.0);
                            }
                        }
                        AudioBufferRef::S24(buf) => {
                            for &sample in buf.chan(0) {
                                let val = sample.inner() as f32;
                                samples.push(val / 8388608.0);
                            }
                        }
                        AudioBufferRef::S32(buf) => {
                            for &sample in buf.chan(0) {
                                samples.push(sample as f32 / 2147483648.0);
                            }
                        }
                        AudioBufferRef::F32(buf) => {
                            for &sample in buf.chan(0) {
                                samples.push(sample);
                            }
                        }
                        AudioBufferRef::F64(buf) => {
                            for &sample in buf.chan(0) {
                                samples.push(sample as f32);
                            }
                        }
                    }
                }
                Err(e) => {
                    return Err(AudioParserError::Decode(format!("{:?}", e)));
                }
            }
        }

        Ok(samples)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audio_parser_basic() {
        // This test would require an actual audio file
        // Just verify the parser compiles
        assert!(true);
    }
}
