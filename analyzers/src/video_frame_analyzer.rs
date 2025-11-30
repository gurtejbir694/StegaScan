use crate::Analyzer;
use image::{DynamicImage, RgbaImage};
use std::fmt::Display;

pub struct VideoFrameAnalyzer;

#[derive(Debug)]
pub enum VideoFrameAnalyzerError {
    FrameProcessing(String),
}

impl Display for VideoFrameAnalyzerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VideoFrameAnalyzerError::FrameProcessing(e) => {
                write!(f, "Frame processing error: {}", e)
            }
        }
    }
}

impl std::error::Error for VideoFrameAnalyzerError {}

#[derive(Debug, Clone)]
pub struct VideoFrameAnalysis {
    pub frame_index: usize,
    pub lsb_suspicious: bool,
    pub chi_square_scores: Vec<f64>,
    pub entropy_scores: Vec<f64>,
    pub histogram_anomalies: bool,
    pub edge_density: f64,
}

impl Analyzer for VideoFrameAnalyzer {
    type Input = DynamicImage;
    type Output = VideoFrameAnalysis;
    type Error = VideoFrameAnalyzerError;

    fn analyze(input: Self::Input) -> Result<Self::Output, Self::Error> {
        let rgba = input.to_rgba8();

        let mut chi_square_scores = Vec::new();
        let mut entropy_scores = Vec::new();

        // Analyze each color channel
        for channel in 0..3 {
            let lsb_plane = extract_lsb_plane(&rgba, channel);
            let chi_square = calculate_chi_square(&lsb_plane);
            let entropy = calculate_entropy(&lsb_plane);

            chi_square_scores.push(chi_square);
            entropy_scores.push(entropy);
        }

        // Check for LSB anomalies
        let lsb_suspicious = chi_square_scores.iter().any(|&score| score > 100.0)
            || entropy_scores.iter().any(|&ent| ent > 0.9);

        // Check histogram anomalies
        let histogram_anomalies = detect_histogram_anomalies(&rgba);

        // Calculate edge density
        let edge_density = calculate_edge_density(&rgba);

        Ok(VideoFrameAnalysis {
            frame_index: 0, // Will be set by caller
            lsb_suspicious,
            chi_square_scores,
            entropy_scores,
            histogram_anomalies,
            edge_density,
        })
    }
}

fn extract_lsb_plane(image: &RgbaImage, channel: usize) -> Vec<u8> {
    image.pixels().map(|pixel| pixel[channel] & 1).collect()
}

fn calculate_chi_square(lsb_data: &[u8]) -> f64 {
    let mut pair_counts = vec![0u32; 4];

    for chunk in lsb_data.chunks(2) {
        if chunk.len() == 2 {
            let pair = (chunk[0] << 1) | chunk[1];
            if (pair as usize) < 4 {
                pair_counts[pair as usize] += 1;
            }
        }
    }

    let total_pairs = lsb_data.len() / 2;
    let expected = total_pairs as f64 / 4.0;

    let mut chi_square = 0.0;
    for &count in &pair_counts {
        let observed = count as f64;
        let diff = observed - expected;
        if expected > 0.0 {
            chi_square += (diff * diff) / expected;
        }
    }

    chi_square
}

fn calculate_entropy(lsb_data: &[u8]) -> f64 {
    let mut counts = [0u32; 2];
    for &bit in lsb_data {
        if bit < 2 {
            counts[bit as usize] += 1;
        }
    }

    let total = lsb_data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy
}

fn detect_histogram_anomalies(image: &RgbaImage) -> bool {
    let mut histograms = vec![vec![0u32; 256]; 3];

    for pixel in image.pixels() {
        for channel in 0..3 {
            histograms[channel][pixel[channel] as usize] += 1;
        }
    }

    for histogram in &histograms {
        let max_count = *histogram.iter().max().unwrap_or(&0);
        let avg_count = histogram.iter().sum::<u32>() / 256;

        if max_count > avg_count * 10 {
            return true;
        }

        for i in 0..128 {
            let even_idx = i * 2;
            let odd_idx = i * 2 + 1;
            let diff = (histogram[even_idx] as i32 - histogram[odd_idx] as i32).abs();

            if diff > (avg_count * 3) as i32 {
                return true;
            }
        }
    }

    false
}

fn calculate_edge_density(image: &RgbaImage) -> f64 {
    let (width, height) = image.dimensions();
    let mut edge_count = 0;
    let total_pixels = (width * height) as f64;

    for y in 1..height - 1 {
        for x in 1..width - 1 {
            for channel in 0..3 {
                let gx = (image.get_pixel(x + 1, y)[channel] as i32
                    - image.get_pixel(x - 1, y)[channel] as i32)
                    .abs();
                let gy = (image.get_pixel(x, y + 1)[channel] as i32
                    - image.get_pixel(x, y - 1)[channel] as i32)
                    .abs();

                let gradient = ((gx * gx + gy * gy) as f64).sqrt();

                if gradient > 30.0 {
                    edge_count += 1;
                    break;
                }
            }
        }
    }

    edge_count as f64 / total_pixels
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgba};

    #[test]
    fn test_lsb_extraction() {
        let img = ImageBuffer::from_fn(10, 10, |x, y| Rgba([(x + y) as u8, 128, 64, 255]));
        let lsb_data = extract_lsb_plane(&img, 0);
        assert_eq!(lsb_data.len(), 100);
    }

    #[test]
    fn test_entropy_calculation() {
        let data = vec![0u8; 100];
        let entropy = calculate_entropy(&data);
        assert!(entropy < 0.1);

        let data: Vec<u8> = (0..100).map(|i| (i % 2) as u8).collect();
        let entropy = calculate_entropy(&data);
        assert!(entropy > 0.9);
    }
}
