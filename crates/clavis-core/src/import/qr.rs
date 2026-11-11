//! Local QR image decoding with hard limits: input <= 10 MiB, decoded image
//! <= 16 megapixels, no remote fetching, no HTML rendering of contents.

use crate::error::CoreError;
use crate::import::{MAX_IMAGE_BYTES, MAX_IMAGE_PIXELS};

/// Decode every QR candidate's text from image bytes (size-limited).
pub fn decode_qr_candidates(bytes: &[u8]) -> Result<Vec<String>, CoreError> {
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(CoreError::ResourceLimit);
    }
    let reader = image::ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| CoreError::InvalidInput("unreadable image"))?;
    let format = reader
        .format()
        .ok_or(CoreError::InvalidInput("unknown image format"))?;
    if !matches!(format, image::ImageFormat::Png | image::ImageFormat::Jpeg) {
        return Err(CoreError::InvalidInput("unsupported image format"));
    }
    let img = reader
        .decode()
        .map_err(|_| CoreError::InvalidInput("unreadable image"))?;
    if img.width() as usize * img.height() as usize > MAX_IMAGE_PIXELS {
        return Err(CoreError::ResourceLimit);
    }
    let mut prepared = rqrr::PreparedImage::prepare(img.to_luma8());
    let codes = prepared.detect_grids();
    let mut out = Vec::new();
    for code in &codes {
        let (_, text) = code
            .decode()
            .map_err(|_| CoreError::InvalidInput("QR code is not decodable"))?;
        out.push(text);
    }
    Ok(out)
}

/// Decode QR codes from image bytes and return the selected candidate's
/// text. If the image contains multiple QR candidates, the caller must pass
/// the user's selection.
pub fn decode_qr_from_image(bytes: &[u8], selection: Option<usize>) -> Result<String, CoreError> {
    let candidates = decode_qr_candidates(bytes)?;
    if candidates.is_empty() {
        return Err(CoreError::InvalidInput("no QR code found in image"));
    }
    if candidates.len() > 1 && selection.is_none() {
        return Err(CoreError::InvalidInput(
            "image contains multiple QR codes; select one",
        ));
    }
    let index = selection.unwrap_or(0);
    candidates
        .into_iter()
        .nth(index)
        .ok_or(CoreError::InvalidInput("QR selection out of range"))
}
