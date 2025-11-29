use crate::Analyzer;
use image::{ImageBuffer, Luma};
use std::fmt::Display;

pub struct SpectrogramAnalyzer;

#[derive(Debug)]
pub enum SpectrogramAnalyzerError {
    AudioProcessing(String),
    FFTError(String),
}

impl Display for SpectrogramAnalyzerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpectrogramAnalyzerError::AudioProcessing(e) => {
                write!(f, "Audio processing error: {}", e)
            }
            SpectrogramAnalyzerError::FFTError(e) => write!(f, "FFT error: {}", e),
        }
    }
}

impl std::error::Error for SpectrogramAnalyzerError {}

#[derive(Debug, Clone)]
pub struct SpectrogramData {
    pub spectrogram_image: ImageBuffer<Luma<u8>, Vec<u8>>,
    pub high_frequency_energy: f64,
    pub suspicious_patterns: Vec<String>,
    pub has_hidden_message: bool,
}

impl Analyzer for SpectrogramAnalyzer {
    type Input = Vec<f32>; // Audio samples
    type Output = SpectrogramData;
    type Error = SpectrogramAnalyzerError;

    fn analyze(input: Self::Input) -> Result<Self::Output, Self::Error> {
        if input.is_empty() {
            return Err(SpectrogramAnalyzerError::AudioProcessing(
                "Empty audio input".to_string(),
            ));
        }

        // Parameters for spectrogram generation
        let window_size = 2048;
        let hop_size = 512;
        let sample_rate = 44100.0;

        // Generate spectrogram
        let spectrogram = generate_spectrogram(&input, window_size, hop_size)?;

        // Analyze high frequency content (where messages are often hidden)
        let high_freq_energy = analyze_high_frequency_energy(&spectrogram, sample_rate);

        // Detect suspicious patterns
        let suspicious_patterns = detect_patterns(&spectrogram);

        // Create visualization
        let spectrogram_image = create_spectrogram_image(&spectrogram);

        // Determine if there might be a hidden message
        let has_hidden_message = high_freq_energy > 0.1 || !suspicious_patterns.is_empty();

        Ok(SpectrogramData {
            spectrogram_image,
            high_frequency_energy: high_freq_energy,
            suspicious_patterns,
            has_hidden_message,
        })
    }
}

fn generate_spectrogram(
    samples: &[f32],
    window_size: usize,
    hop_size: usize,
) -> Result<Vec<Vec<f32>>, SpectrogramAnalyzerError> {
    use rustfft::{FftPlanner, num_complex::Complex};

    let mut planner = FftPlanner::new();
    let fft = planner.plan_fft_forward(window_size);

    let mut spectrogram = Vec::new();
    let num_frames = (samples.len() - window_size) / hop_size + 1;

    // Hann window for smoothing
    let window: Vec<f32> = (0..window_size)
        .map(|i| {
            0.5 * (1.0
                - ((2.0 * std::f32::consts::PI * i as f32) / (window_size as f32 - 1.0)).cos())
        })
        .collect();

    for frame_idx in 0..num_frames {
        let start = frame_idx * hop_size;
        let end = start + window_size;

        if end > samples.len() {
            break;
        }

        // Apply window and convert to complex
        let mut buffer: Vec<Complex<f32>> = samples[start..end]
            .iter()
            .zip(window.iter())
            .map(|(&s, &w)| Complex::new(s * w, 0.0))
            .collect();

        // Perform FFT
        fft.process(&mut buffer);

        // Calculate magnitude spectrum (only first half due to symmetry)
        let magnitudes: Vec<f32> = buffer[..window_size / 2]
            .iter()
            .map(|c| (c.re * c.re + c.im * c.im).sqrt())
            .collect();

        spectrogram.push(magnitudes);
    }

    Ok(spectrogram)
}

fn analyze_high_frequency_energy(spectrogram: &[Vec<f32>], sample_rate: f32) -> f64 {
    if spectrogram.is_empty() {
        return 0.0;
    }

    let num_bins = spectrogram[0].len();
    let freq_per_bin = sample_rate / (2.0 * num_bins as f32);

    // Focus on frequencies above 15 kHz (where messages are often hidden)
    let high_freq_threshold = 15000.0;
    let start_bin = (high_freq_threshold / freq_per_bin) as usize;

    let mut total_energy = 0.0;
    let mut high_freq_energy = 0.0;

    for frame in spectrogram {
        for (i, &magnitude) in frame.iter().enumerate() {
            let energy = magnitude * magnitude;
            total_energy += energy as f64;

            if i >= start_bin {
                high_freq_energy += energy as f64;
            }
        }
    }

    if total_energy > 0.0 {
        high_freq_energy / total_energy
    } else {
        0.0
    }
}

fn detect_patterns(spectrogram: &[Vec<f32>]) -> Vec<String> {
    let mut patterns = Vec::new();

    if spectrogram.is_empty() {
        return patterns;
    }

    let num_bins = spectrogram[0].len();
    let num_frames = spectrogram.len();

    // Check for unusual horizontal lines (constant frequencies)
    for bin in num_bins / 2..num_bins {
        let mut consecutive_high = 0;
        for frame in spectrogram {
            if frame[bin] > 0.5 {
                consecutive_high += 1;
            } else {
                consecutive_high = 0;
            }

            if consecutive_high > num_frames / 4 {
                patterns.push(format!(
                    "Persistent high-frequency tone at bin {} (possible hidden data)",
                    bin
                ));
                break;
            }
        }
    }

    // Check for geometric patterns (text/images in spectrogram)
    let edge_count = detect_edges(spectrogram);
    if edge_count > (num_frames * num_bins) / 20 {
        patterns.push("High edge density detected (possible hidden image/text)".to_string());
    }

    // Check for unusual energy distribution
    let mut high_energy_frames = 0;
    for frame in spectrogram {
        let max_magnitude = frame.iter().fold(0.0f32, |a, &b| a.max(b));
        let avg_magnitude = frame.iter().sum::<f32>() / frame.len() as f32;

        if max_magnitude > 5.0 * avg_magnitude {
            high_energy_frames += 1;
        }
    }

    if high_energy_frames > num_frames / 10 {
        patterns.push("Unusual energy spikes detected".to_string());
    }

    patterns
}

fn detect_edges(spectrogram: &[Vec<f32>]) -> usize {
    let mut edge_count = 0;

    for i in 1..spectrogram.len() {
        for j in 1..spectrogram[0].len() {
            let current = spectrogram[i][j];
            let left = spectrogram[i - 1][j];
            let top = spectrogram[i][j - 1];

            // Simple edge detection (large gradient)
            if (current - left).abs() > 0.3 || (current - top).abs() > 0.3 {
                edge_count += 1;
            }
        }
    }

    edge_count
}

fn create_spectrogram_image(spectrogram: &[Vec<f32>]) -> ImageBuffer<Luma<u8>, Vec<u8>> {
    if spectrogram.is_empty() {
        return ImageBuffer::new(1, 1);
    }

    let width = spectrogram.len() as u32;
    let height = spectrogram[0].len() as u32;

    // Find max value for normalization
    let max_val = spectrogram
        .iter()
        .flat_map(|frame| frame.iter())
        .fold(0.0f32, |a, &b| a.max(b));

    ImageBuffer::from_fn(width, height, |x, y| {
        let frame = &spectrogram[x as usize];
        let bin = (height - 1 - y) as usize; // Flip vertically

        if bin < frame.len() {
            // Apply logarithmic scaling for better visualization
            let normalized = if max_val > 0.0 {
                (frame[bin] / max_val).min(1.0)
            } else {
                0.0
            };

            let log_scaled = (1.0 + normalized * 99.0).log10() / 2.0; // log10(100) = 2
            let pixel_value = (log_scaled * 255.0) as u8;

            Luma([pixel_value])
        } else {
            Luma([0])
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spectrogram_generation() {
        // Generate a simple sine wave
        let sample_rate = 44100.0;
        let duration = 1.0;
        let frequency = 440.0; // A4 note

        let samples: Vec<f32> = (0..(sample_rate * duration) as usize)
            .map(|i| {
                let t = i as f32 / sample_rate;
                (2.0 * std::f32::consts::PI * frequency * t).sin()
            })
            .collect();

        let result = SpectrogramAnalyzer::analyze(samples);
        assert!(result.is_ok());

        let data = result.unwrap();
        assert!(!data.spectrogram_image.dimensions().0 == 0);
    }
}
