use std::fmt::Display;

use image::{DynamicImage, ImageBuffer, RgbaImage};

use crate::Analyzer;

pub struct ImageFilterAnalyzer;

#[derive(Debug)]
pub enum ImageFilterErrors {}

impl Display for ImageFilterErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

impl Analyzer for ImageFilterAnalyzer {
    type Output = Vec<RgbaImage>;

    type Input = DynamicImage;

    type Error = ImageFilterErrors;

    fn analyze(input: Self::Input) -> Result<Self::Output, Self::Error> {
        let mut output = Vec::new();
        output.push(input.clone().into_rgba8());
        output.push(
            ImageBuffer::from_vec(
                input.width(),
                input.height(),
                input
                    .clone()
                    .into_rgba8()
                    .pixels()
                    .flat_map(|p| return [p[0], 0, 0, 0])
                    .collect::<Vec<u8>>(),
            )
            .expect("to be able to make an image that is single channel from the original image"),
        );
        output.push(
            ImageBuffer::from_vec(
                input.width(),
                input.height(),
                input
                    .clone()
                    .into_rgba8()
                    .pixels()
                    .flat_map(|p| return [0, p[1], 0, 0])
                    .collect::<Vec<u8>>(),
            )
            .expect("to be able to make an image that is single channel from the original image"),
        );
        output.push(
            ImageBuffer::from_vec(
                input.width(),
                input.height(),
                input
                    .clone()
                    .into_rgba8()
                    .pixels()
                    .flat_map(|p| return [0, 0, p[2], 0])
                    .collect::<Vec<u8>>(),
            )
            .expect("to be able to make an image that is single channel from the original image"),
        );
        output.push(
            ImageBuffer::from_vec(
                input.width(),
                input.height(),
                input
                    .clone()
                    .into_rgba8()
                    .pixels()
                    .flat_map(|p| return [0, 0, 0, p[3]])
                    .collect::<Vec<u8>>(),
            )
            .expect("to be able to make an image that is single channel from the original image"),
        );
        output.push(
            ImageBuffer::from_vec(
                input.width(),
                input.height(),
                input
                    .clone()
                    .into_rgba8()
                    .pixels()
                    .flat_map(|p| return [p[0], 255, 255, 255])
                    .collect::<Vec<u8>>(),
            )
            .expect("to be able to make an image that is single channel from the original image"),
        );
        output.push(
            ImageBuffer::from_vec(
                input.width(),
                input.height(),
                input
                    .clone()
                    .into_rgba8()
                    .pixels()
                    .flat_map(|p| return [255, p[1], 255, 255])
                    .collect::<Vec<u8>>(),
            )
            .expect("to be able to make an image that is single channel from the original image"),
        );
        output.push(
            ImageBuffer::from_vec(
                input.width(),
                input.height(),
                input
                    .clone()
                    .into_rgba8()
                    .pixels()
                    .flat_map(|p| return [255, 255, p[2], 255])
                    .collect::<Vec<u8>>(),
            )
            .expect("to be able to make an image that is single channel from the original image"),
        );
        output.push(
            ImageBuffer::from_vec(
                input.width(),
                input.height(),
                input
                    .clone()
                    .into_rgba8()
                    .pixels()
                    .flat_map(|p| return [255, 255, 255, p[3]])
                    .collect::<Vec<u8>>(),
            )
            .expect("to be able to make an image that is single channel from the original image"),
        );
        output.push(input.adjust_contrast(-10.0).into_rgba8());
        output.push(input.adjust_contrast(10.0).into_rgba8());
        Ok(output)
    }
}
