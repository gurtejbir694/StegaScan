use crate::Analyzer;
use image::{DynamicImage, ImageBuffer, Rgba, RgbaImage};
use std::fmt::Display;

pub struct LsbAnalyzer;

#[derive(Debug)]
pub enum LsbAnalyzerError {
    ImageProcessing(String),
}

impl Display for LsbAnalyzerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LsbAnalyzerError::ImageProcessing(e) => write!(f, "Image processing error: {}", e),
        }
    }
}

impl std::error::Error for LsbAnalyzerError {}

#[derive(Debug, Clone)]
pub struct LsbAnalysis {
    pub lsb_planes: Vec<RgbaImage>,
    pub chi_square_scores: Vec<f64>,
    pub entropy_scores: Vec<f64>,
    pub suspicious: bool,
}

impl Analyzer for LsbAnalyzer {
    type Input = DynamicImage;
    type Output = LsbAnalysis;
    type Error = LsbAnalyzerError;

    fn analyze(input: Self::Input) -> Result<Self::Output, Self::Error> {
        let rgba = input.to_rgba8();

        let mut lsb_planes = Vec::new();
        let mut chi_square_scores = Vec::new();
        let mut entropy_scores = Vec::new();

        // Extract LSB from each color channel (R, G, B)
        for channel in 0..3 {
            // Extract LSB plane
            let lsb_plane = extract_lsb_plane(&rgba, channel);

            // Calculate chi-square test for randomness
            let chi_square = calculate_chi_square(&lsb_plane, channel);
            chi_square_scores.push(chi_square);

            // Calculate entropy
            let entropy = calculate_entropy(&lsb_plane, channel);
            entropy_scores.push(entropy);

            // Create visualization of LSB plane (amplified for visibility)
            let visualized = visualize_lsb_plane(&lsb_plane, channel);
            lsb_planes.push(visualized);
        }

        // Determine if image is suspicious
        // High chi-square or low entropy suggests hidden data
        let suspicious = chi_square_scores.iter().any(|&score| score > 100.0)
            || entropy_scores.iter().any(|&ent| ent > 0.9);

        Ok(LsbAnalysis {
            lsb_planes,
            chi_square_scores,
            entropy_scores,
            suspicious,
        })
    }
}

fn extract_lsb_plane(image: &RgbaImage, channel: usize) -> Vec<u8> {
    image.pixels().map(|pixel| pixel[channel] & 1).collect()
}

fn visualize_lsb_plane(lsb_data: &[u8], channel: usize) -> RgbaImage {
    let width = (lsb_data.len() as f64).sqrt().ceil() as u32;
    let height = (lsb_data.len() as u32 + width - 1) / width;

    ImageBuffer::from_fn(width, height, |x, y| {
        let idx = (y * width + x) as usize;
        if idx < lsb_data.len() {
            let val = if lsb_data[idx] == 1 { 255 } else { 0 };
            match channel {
                0 => Rgba([val, 0, 0, 255]),     // Red channel
                1 => Rgba([0, val, 0, 255]),     // Green channel
                2 => Rgba([0, 0, val, 255]),     // Blue channel
                _ => Rgba([val, val, val, 255]), // Grayscale fallback
            }
        } else {
            Rgba([0, 0, 0, 255])
        }
    })
}

fn calculate_chi_square(lsb_data: &[u8], _channel: usize) -> f64 {
    // Chi-square test for detecting non-random patterns in LSB
    // Compares pairs of values (PoV analysis)

    let mut pair_counts = vec![0u32; 256];

    for chunk in lsb_data.chunks(2) {
        if chunk.len() == 2 {
            let pair = (chunk[0] << 1) | chunk[1];
            pair_counts[pair as usize] += 1;
        }
    }

    let total_pairs = lsb_data.len() / 2;
    let expected = total_pairs as f64 / 4.0; // Expected frequency for each pair

    let mut chi_square = 0.0;
    for &count in pair_counts.iter().take(4) {
        let observed = count as f64;
        let diff = observed - expected;
        chi_square += (diff * diff) / expected;
    }

    chi_square
}

fn calculate_entropy(lsb_data: &[u8], _channel: usize) -> f64 {
    // Calculate Shannon entropy of LSB data
    // High entropy (close to 1 for binary) suggests randomness/encryption

    let mut counts = [0u32; 2];
    for &bit in lsb_data {
        counts[bit as usize] += 1;
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

#[cfg(test)]
mod tests {
    use super::*;
    use image::Rgba;

    #[test]
    fn test_lsb_extraction() {
        let img = ImageBuffer::from_fn(10, 10, |x, y| Rgba([(x + y) as u8, 128, 64, 255]));

        let lsb_data = extract_lsb_plane(&img, 0);
        assert_eq!(lsb_data.len(), 100);
    }

    #[test]
    fn test_entropy_calculation() {
        // All zeros - minimum entropy
        let data = vec![0u8; 100];
        let entropy = calculate_entropy(&data, 0);
        assert!(entropy < 0.1);

        // Alternating pattern - maximum entropy for binary
        let data: Vec<u8> = (0..100).map(|i| i % 2).collect();
        let entropy = calculate_entropy(&data, 0);
        assert!(entropy > 0.9);
    }
}
