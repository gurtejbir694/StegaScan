use crate::Parser;
use ffmpeg_next as ffmpeg;
use image::{ImageBuffer, RgbaImage};
use std::fmt::Display;
use std::path::Path;

pub struct VideoParser;

#[derive(Debug)]
pub enum VideoParserError {
    IO(std::io::Error),
    Ffmpeg(ffmpeg::Error),
    Decode(String),
}

impl Display for VideoParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for VideoParserError {}

impl From<std::io::Error> for VideoParserError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl From<ffmpeg::Error> for VideoParserError {
    fn from(e: ffmpeg::Error) -> Self {
        Self::Ffmpeg(e)
    }
}

pub struct VideoFrameIterator {
    input: ffmpeg::format::context::Input,
    decoder: ffmpeg::decoder::Video,
    scaler: ffmpeg::software::scaling::Context,
    video_stream_index: usize,
    decoded: ffmpeg::frame::Video,
    packet_buffer: Vec<(usize, ffmpeg::codec::packet::Packet)>,
    packet_index: usize,
    packets_exhausted: bool,
    flushing: bool,
}

impl VideoFrameIterator {
    pub fn new<P: AsRef<Path>>(file_path: &P) -> Result<Self, VideoParserError> {
        ffmpeg::init()?;

        let mut input = ffmpeg::format::input(file_path.as_ref())?;
        let video_stream =
            input
                .streams()
                .best(ffmpeg::media::Type::Video)
                .ok_or(VideoParserError::Decode(
                    "No video stream found".to_string(),
                ))?;
        let video_stream_index = video_stream.index();

        let context = ffmpeg::codec::context::Context::from_parameters(video_stream.parameters())?;
        let decoder = context.decoder().video()?;

        let scaler = ffmpeg::software::scaling::Context::get(
            decoder.format(),
            decoder.width(),
            decoder.height(),
            ffmpeg::format::Pixel::RGBA,
            decoder.width(),
            decoder.height(),
            ffmpeg::software::scaling::Flags::BILINEAR,
        )?;

        let decoded = ffmpeg::frame::Video::empty();

        Ok(Self {
            input,
            decoder,
            scaler,
            video_stream_index,
            decoded,
            packet_buffer: Vec::new(),
            packet_index: 0,
            packets_exhausted: false,
            flushing: false,
        })
    }

    fn load_packets(&mut self, count: usize) {
        if self.packets_exhausted {
            return;
        }

        let mut loaded = 0;
        for (stream, packet) in self.input.packets() {
            if stream.index() == self.video_stream_index {
                self.packet_buffer.push((stream.index(), packet));
                loaded += 1;
                if loaded >= count {
                    return;
                }
            }
        }
        self.packets_exhausted = true;
    }

    fn decode_frame(&mut self) -> Result<Option<RgbaImage>, VideoParserError> {
        if self.decoder.receive_frame(&mut self.decoded).is_ok() {
            let mut rgba_frame = ffmpeg::frame::Video::empty();
            self.scaler.run(&self.decoded, &mut rgba_frame)?;

            let width = rgba_frame.width();
            let height = rgba_frame.height();
            let data = rgba_frame.data(0);

            let img = ImageBuffer::from_raw(width, height, data.to_vec()).ok_or_else(|| {
                VideoParserError::Decode("Failed to create RGBA buffer".to_string())
            })?;

            return Ok(Some(img));
        }
        Ok(None)
    }
}

impl Iterator for VideoFrameIterator {
    type Item = Result<RgbaImage, VideoParserError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Try to decode any buffered frames first
            match self.decode_frame() {
                Ok(Some(frame)) => return Some(Ok(frame)),
                Ok(None) => {} // No buffered frames, continue
                Err(e) => return Some(Err(e)),
            }

            // If we're flushing and no frames left, we're done
            if self.flushing {
                return None;
            }

            // Load more packets if buffer is empty
            if self.packet_index >= self.packet_buffer.len() {
                if self.packets_exhausted {
                    // No more packets, flush the decoder
                    if let Err(e) = self.decoder.send_eof() {
                        return Some(Err(e.into()));
                    }
                    self.flushing = true;
                    continue;
                }

                self.packet_buffer.clear();
                self.packet_index = 0;
                self.load_packets(10); // Load 10 packets at a time

                if self.packet_buffer.is_empty() && self.packets_exhausted {
                    // No more packets, flush the decoder
                    if let Err(e) = self.decoder.send_eof() {
                        return Some(Err(e.into()));
                    }
                    self.flushing = true;
                    continue;
                }
            }

            // Process next packet
            if self.packet_index < self.packet_buffer.len() {
                let (_stream_index, packet) = &self.packet_buffer[self.packet_index];
                if let Err(e) = self.decoder.send_packet(packet) {
                    return Some(Err(e.into()));
                }
                self.packet_index += 1;
            }
        }
    }
}

impl Parser for VideoParser {
    type Output = VideoFrameIterator;
    type Error = VideoParserError;

    fn parse_path<P>(file_path: &P) -> Result<Self::Output, Self::Error>
    where
        P: AsRef<Path>,
    {
        VideoFrameIterator::new(file_path)
    }
}
