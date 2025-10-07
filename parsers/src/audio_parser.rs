use crate::Parser;
use std::fmt::Display;
use std::fs::File;
use std::io;
use std::path::Path;
use symphonia::core::audio::AudioBufferRef;
use symphonia::core::codecs::{CODEC_TYPE_NULL, DecoderOptions};
use symphonia::core::errors::Error as SymphoniaError;
use symphonia::core::formats::FormatOptions;
use symphonia::core::io::MediaSourceStream;

pub struct AudioParser;

#[derive(Debug)]
pub enum AudioParserError {
    IO(io::Error),
    Symphonia(SymphoniaError),
    Decode(String),
}

impl Display for AudioParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

impl std::error::Error for AudioParserError {}

impl From<io::Error> for AudioParserError {
    fn from(value: io::Error) -> Self {
        Self::IO(value)
    }
}

impl From<SymphoniaError> for AudioParserError {
    fn from(value: SymphoniaError) -> Self {
        Self::Symphonia(value)
    }
}

impl Parser for AudioParser {
    type Output = Vec<f32>; // Decoded interleaved samples
    type Error = AudioParserError;

    fn parse_path<P>(file_path: &P) -> Result<Self::Output, Self::Error>
    where
        P: AsRef<Path>,
    {
        let file = File::open(file_path)?;
        let mss = MediaSourceStream::new(Box::new(file), Default::default());

        let probed = symphonia::default::get_probe()
            .format(
                &Default::default(),
                mss,
                &FormatOptions {
                    enable_gapless: true,
                    ..Default::default()
                },
                &Default::default(),
            )
            .map_err(AudioParserError::Symphonia)?;

        let mut format = probed.format;
        let track = format
            .default_track()
            .ok_or(AudioParserError::Decode("No default track".to_string()))?;

        // Extract track ID and codec params before the loop to avoid borrow issues
        let track_id = track.id;
        let codec_params = track.codec_params.clone();

        if codec_params.codec != CODEC_TYPE_NULL {
            let mut decoder = symphonia::default::get_codecs()
                .make(&codec_params, &DecoderOptions::default())
                .map_err(|e| AudioParserError::Symphonia(e))?;

            let mut samples = Vec::new();

            loop {
                match format.next_packet() {
                    Ok(packet) => {
                        if packet.track_id() != track_id {
                            continue;
                        }
                        match decoder.decode(&packet) {
                            Ok(decoded) => {
                                match decoded {
                                    AudioBufferRef::F32(buffer) => {
                                        // Use Signal trait to get planes and iterate over samples
                                        for plane in buffer.planes().planes() {
                                            samples.extend_from_slice(plane);
                                        }
                                    }
                                    _ => {
                                        return Err(AudioParserError::Decode(
                                            "Unsupported audio buffer type".to_string(),
                                        ));
                                    }
                                }
                            }
                            Err(e) => return Err(AudioParserError::Symphonia(e)),
                        }
                    }
                    Err(SymphoniaError::IoError(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                        break;
                    }
                    Err(e) => return Err(AudioParserError::Symphonia(e)),
                }
            }
            Ok(samples)
        } else {
            Err(AudioParserError::Decode("Unsupported codec".to_string()))
        }
    }
}
