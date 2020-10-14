// taken from https://github.com/WanzenBug/g2p version 0.4.0

use crate::decode::g2poly::G2Poly;
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub, SubAssign};

/// Common trait for finite fields
///
/// All types generated by `g2p!` implement this trait.
/// The trait ensures that all the expected operations of a finite field are implemented.
///
/// In addition, some often used constants like `ONE` and `ZERO` are exported, as well as the more
/// esoteric `GENERATOR`.
pub trait GaloisField:
    Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + SubAssign
    + Mul<Output = Self>
    + MulAssign
    + Div<Output = Self>
    + DivAssign
    + Copy
    + PartialEq
    + Eq
{
    /// Number of elements in the field
    const SIZE: usize;

    /// The value 0 as a finite field constant
    const ZERO: Self;

    /// The value 1 as a finite field constant
    const ONE: Self;

    /// A generator of the multiplicative group of a finite field
    /// The powers of this element will generate all non-zero elements of the finite field
    /// ```rust
    /// use qr_code::decode::g2p::{self, GaloisField};
    /// use qr_code::decode::gf16::GF16;
    ///
    /// let mut g = GF16::GENERATOR;
    /// let mut set = std::collections::HashSet::new();
    /// for _ in 0..15 {
    ///     g *= GF16::GENERATOR;
    ///     set.insert(g);
    /// }
    /// assert_eq!(set.len(), 15);
    /// ```
    const GENERATOR: Self;

    /// Polynomial representation of the modulus used to generate the field
    const MODULUS: G2Poly;

    /// Calculate the p-th power of a value
    ///
    /// Calculate the value of x to the power p in finite field arithmethic
    ///
    /// # Example
    /// ```rust
    /// use qr_code::decode::g2p::{self, GaloisField};
    /// use qr_code::decode::gf16::GF16;
    ///
    /// # fn main() {
    /// let g: GF16 = 2.into();
    /// assert_eq!(g.pow(0), GF16::ONE);
    /// assert_eq!(g.pow(1), g);
    /// assert_eq!(g.pow(2), 4.into());
    /// assert_eq!(g.pow(3), 8.into());
    /// assert_eq!(g.pow(4), 3.into());
    /// # }
    /// ```
    fn pow(self, p: usize) -> Self {
        let mut val = Self::ONE;
        let mut pow_pos = 1 << (::std::mem::size_of::<usize>() * 8 - 1);
        assert_eq!(pow_pos << 1, 0);
        while pow_pos > 0 {
            val *= val;
            if (pow_pos & p) > 0 {
                val *= self;
            }
            pow_pos >>= 1;
        }
        val
    }
}
