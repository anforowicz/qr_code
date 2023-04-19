//!
//! qr_code
//!
//! This crate provides a [QrCode](crate::QrCode) encoder and decoder
//!

#![deny(missing_docs)]
#![deny(warnings)]
#![allow(
    clippy::must_use_candidate, // This is just annoying.
    clippy::use_self, // Rust 1.33 doesn't support Self::EnumVariant, let's try again in 1.37.
    clippy::match_like_matches_macro, // MSRV is lower than what's needed for matches!
)]
// TODO: Fix coverage of examples from our README.md - apparently the incantation below is not
// sufficient for this.
#![cfg_attr(feature = "bench", doc = include_str!("../README.md"))]
#![cfg_attr(docsrs, feature(doc_cfg))]
// Using `#[bench]`, `test::Bencher`, and `cargo bench` requires opting into the unstable `test`
// feature.  See https://github.com/rust-lang/rust/issues/50297 for more details.  Unstable
// features are only available in the nightly versions of the Rust compiler - to keep stable
// builds working we only enable benching behind the "bench" feature.
#![cfg_attr(feature = "bench", feature(test))]
#[cfg(feature = "bench")]
extern crate test;

// Re-exported dependencies.
#[cfg(feature = "bmp")]
pub extern crate bmp_monochrome;

use std::ops::Index;

pub mod bits;
pub mod canvas;
mod cast;
pub mod ec;
pub mod optimize;
mod render;
pub mod types;

#[cfg(feature = "fuzz")]
mod fuzz;
#[cfg(feature = "fuzz")]
pub use crate::fuzz::{split_merge_rt, QrCodeData};

#[cfg(all(feature = "bmp", feature = "decode"))]
pub mod decode;
pub mod structured;

pub use crate::types::{Color, EcLevel, QrResult, Version};

use crate::cast::As;

/// The encoded QR code symbol.
#[derive(Clone, Debug)]
pub struct QrCode {
    content: Vec<Color>,
    version: Version,
    ec_level: EcLevel,
    width: usize,
}

impl QrCode {
    /// Constructs a new QR code which automatically encodes the given data.
    ///
    /// This method uses the "medium" error correction level and automatically
    /// chooses the smallest QR code.
    ///
    ///     use qr_code::QrCode;
    ///
    ///     let code = QrCode::new(b"Some data").unwrap();
    ///
    /// # Errors
    ///
    /// Returns error if the QR code cannot be constructed, e.g. when the data
    /// is too long.
    pub fn new<D: AsRef<[u8]>>(data: D) -> QrResult<Self> {
        Self::with_error_correction_level(data, EcLevel::M)
    }

    /// Constructs a new QR code which automatically encodes the given data at a
    /// specific error correction level.
    ///
    /// This method automatically chooses the smallest QR code.
    ///
    ///     use qr_code::{QrCode, EcLevel};
    ///
    ///     let code = QrCode::with_error_correction_level(b"Some data", EcLevel::H).unwrap();
    ///
    /// # Errors
    ///
    /// Returns error if the QR code cannot be constructed, e.g. when the data
    /// is too long.
    pub fn with_error_correction_level<D: AsRef<[u8]>>(
        data: D,
        ec_level: EcLevel,
    ) -> QrResult<Self> {
        let bits = bits::encode_auto(data.as_ref(), ec_level)?;
        Self::with_bits(bits, ec_level)
    }

    /// Constructs a new QR code for the given version and error correction
    /// level.
    ///
    ///     use qr_code::{QrCode, Version, EcLevel};
    ///
    ///     let code = QrCode::with_version(b"Some data", Version::Normal(5), EcLevel::M).unwrap();
    ///
    /// This method can also be used to generate Micro QR code.
    ///
    ///     use qr_code::{QrCode, Version, EcLevel};
    ///
    ///     let micro_code = QrCode::with_version(b"123", Version::Micro(1), EcLevel::L).unwrap();
    ///
    /// # Errors
    ///
    /// Returns error if the QR code cannot be constructed, e.g. when the data
    /// is too long, or when the version and error correction level are
    /// incompatible.
    pub fn with_version<D: AsRef<[u8]>>(
        data: D,
        version: Version,
        ec_level: EcLevel,
    ) -> QrResult<Self> {
        let mut bits = bits::Bits::new(version);
        bits.push_optimal_data(data.as_ref())?;
        bits.push_terminator(ec_level)?;
        Self::with_bits(bits, ec_level)
    }

    /// Constructs a new QR code with encoded bits.
    ///
    /// Use this method only if there are very special need to manipulate the
    /// raw bits before encoding. Some examples are:
    ///
    /// * Encode data using specific character set with ECI
    /// * Use the FNC1 modes
    /// * Avoid the optimal segmentation algorithm
    ///
    /// See the `Bits` structure for detail.
    ///
    ///     #![allow(unused_must_use)]
    ///
    ///     use qr_code::{QrCode, Version, EcLevel};
    ///     use qr_code::bits::Bits;
    ///
    ///     let mut bits = Bits::new(Version::Normal(1));
    ///     bits.push_eci_designator(9);
    ///     bits.push_byte_data(b"\xca\xfe\xe4\xe9\xea\xe1\xf2 QR");
    ///     bits.push_terminator(EcLevel::L);
    ///     let qrcode = QrCode::with_bits(bits, EcLevel::L);
    ///
    /// # Errors
    ///
    /// Returns error if the QR code cannot be constructed, e.g. when the bits
    /// are too long, or when the version and error correction level are
    /// incompatible.
    pub fn with_bits(bits: bits::Bits, ec_level: EcLevel) -> QrResult<Self> {
        let version = bits.version();
        let data = bits.into_bytes();
        let (encoded_data, ec_data) = ec::construct_codewords(&*data, version, ec_level)?;
        let mut canvas = canvas::Canvas::new(version, ec_level);
        canvas.draw_all_functional_patterns();
        canvas.draw_data(&*encoded_data, &*ec_data);
        let canvas = canvas.apply_best_mask();
        Ok(Self {
            content: canvas.into_colors(),
            version,
            ec_level,
            width: version.width().as_usize(),
        })
    }

    /// Gets the version of this QR code.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Gets the error correction level of this QR code.
    pub fn error_correction_level(&self) -> EcLevel {
        self.ec_level
    }

    /// Gets the number of modules per side, i.e. the width of this QR code.
    ///
    /// The width here does not contain the quiet zone paddings.
    pub fn width(&self) -> usize {
        self.width
    }

    /// Gets the maximum number of allowed erratic modules can be introduced
    /// before the data becomes corrupted. Note that errors should not be
    /// introduced to functional modules.
    pub fn max_allowed_errors(&self) -> usize {
        ec::max_allowed_errors(self.version, self.ec_level).expect("invalid version or ec_level")
    }

    /// Checks whether a module at coordinate (x, y) is a functional module or
    /// not.
    pub fn is_functional(&self, x: usize, y: usize) -> bool {
        let x = x.as_i16();
        let y = y.as_i16();
        canvas::is_functional(self.version, self.version.width(), x, y)
    }

    /// Converts the QR code to a vector of booleans. Each entry represents the
    /// color of the module, with "true" means dark and "false" means light.
    pub fn to_vec(&self) -> Vec<bool> {
        self.content.iter().map(|c| *c != Color::Light).collect()
    }

    /// Returns an iterator over QR code vector of colors.
    pub fn iter(&self) -> QrCodeIterator {
        QrCodeIterator::new(&self)
    }

    /// Converts the QR code to a vector of colors.
    pub fn into_colors(self) -> Vec<Color> {
        self.content
    }
}

impl Index<(usize, usize)> for QrCode {
    type Output = Color;

    fn index(&self, (x, y): (usize, usize)) -> &Color {
        let index = y * self.width + x;
        &self.content[index]
    }
}

/// Iterate over QR code data without consuming the QR code struct
pub struct QrCodeIterator<'a> {
    qr_code: &'a QrCode,
    index: usize,
}

impl<'a> QrCodeIterator<'a> {
    fn new(qr_code: &'a QrCode) -> Self {
        let index = 0;
        QrCodeIterator { qr_code, index }
    }
}

impl<'a> Iterator for QrCodeIterator<'a> {
    type Item = bool;
    fn next(&mut self) -> Option<bool> {
        let result = self
            .qr_code
            .content
            .get(self.index)
            .map(|c| c == &Color::Dark);
        self.index += 1;
        result
    }
}

#[cfg(all(feature = "bmp", feature = "decode"))]
#[cfg(test)]
mod tests {

    #[test]
    fn test_rt() {
        use crate::decode::BmpDecode;
        use crate::QrCode;
        use bmp_monochrome::Bmp;
        use rand::distributions::Alphanumeric;
        use rand::Rng;
        use std::io::Cursor;

        let rand_string: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(30)
            .collect();
        let qr_code = QrCode::new(rand_string.as_bytes()).unwrap();
        let mut cursor = Cursor::new(vec![]);
        qr_code
            .to_bmp()
            .mul(3)
            .unwrap()
            .add_white_border(3)
            .unwrap()
            .write(&mut cursor)
            .unwrap();
        cursor.set_position(0);
        let bmp = Bmp::read(cursor).unwrap();
        let result = bmp.normalize().decode().unwrap();
        let decoded = std::str::from_utf8(&result).unwrap();
        assert_eq!(rand_string, decoded);
    }
}

#[cfg(feature = "bench")]
pub(crate) mod bench {
    use super::{EcLevel, QrCode};

    /// Benchmark of base64 input seems like a useful data point because:
    /// * base64 data is a mixture of digits (`Mode::Numeric`), uppercase letters
    ///   (`Mode::Alphanumeric`), and lowercase letters (`Mode::Byte`) and therefore
    ///   should provide fair coverage of parsing and optimization code
    /// * base64 data is somewhat realistic - e.g. one common scenario for QR codes
    ///   is encoding arbitrary URLs and base64 may appear in query part of URLs.
    ///
    /// The specific base64 input data below has been taken from
    /// https://cryptopals.com/sets/1/challenges/6 and truncated to 2880 characters
    /// (roughly the upper capacity of `Mode::Byte` segments in version 40, `EcLevel::L`
    /// according to https://www.qrcode.com/en/about/version.html).
    pub const BASE64_EXAMPLE: &[u8] = b"\
        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\
        BxscEDMNUhkBC0ETBxdULFUAJQAGARFJGk9FVAYGGlMNMRcXTRoBDxNPeG43\
        TQA7HRxJFUVUCQhBFAoNUwctRQYFDE43PT9SUDdJUydcSWRtcwANFVAHAU5T\
        FjtFGgwbCkEYBhlFeFsABRcbAwZOVCYEWgdPYyARNRcGAQwKQRYWUlQwXwAg\
        ExoLFAAcARFUBwFOUwImCgcDDU5rIAcXUj0dU2IcBk4TUh0YFUkASEkcC3QI\
        GwMMQkE9SB8AMk9TNlIOCxNUHQZCAAoAHh1FXjYCDBsFABkOBkk7FgALVQRO\
        D0EaDwxOSU8dGgI8EVIBAAUEVA5SRjlUQTYbCk5teRsdRVQcDhkDADBFHwhJ\
        AQ8XClJBNl4AC1IdBghVEwARABoHCAdFXjwdGEkDCBMHBgAwW1YnUgAaRyon\
        B0VTGgoZUwE7EhxNCAAFVAMXTjwaTSdSEAESUlQNBFJOZU5LXHQMHE0EF0EA\
        Bh9FeRp5LQdFTkAZREgMU04CEFMcMQQAQ0lkay0ABwcqXwA1FwgFAk4dBkIA\
        CA4aB0l0PD1MSQ8PEE87ADtbTmIGDAILAB0cRSo3ABwBRTYKFhROHUETCgZU\
        MVQHYhoGGksABwdJAB0ASTpFNwQcTRoDBBgDUkksGioRHUkKCE5THEVCC08E\
        EgF0BBwJSQoOGkgGADpfADETDU5tBzcJEFMLTx0bAHQJCx8ADRJUDRdMN1RH";

    #[bench]
    fn bench_qr_code_with_low_ecc(bencher: &mut test::Bencher) {
        bencher.iter(|| {
            // Using `EcLevel::L` because otherwise the input data won't fit and we'll get
            // `DataTooLong` error.
            let qr_code = QrCode::with_error_correction_level(BASE64_EXAMPLE, EcLevel::L).unwrap();

            // The code below reads all the QR pixels - this is a haphazard attempt to ensure that
            // the compiler won't optimize away generation of the data.
            qr_code.iter().map(|b| if b { 1 } else { 0 }).sum::<usize>()
        });
    }
}
