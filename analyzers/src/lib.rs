pub mod image_filter;

pub trait Analyzer {
    type Output;
    type Input;
    type Error;

    fn analyze(input: Self::Input) -> Result<Self::Output, Self::Error>;
}
