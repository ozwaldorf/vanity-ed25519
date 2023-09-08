type Point = [u8; 32];

pub struct MulLut {
    table: [[Point; 256]; 32],
}

impl MulLut {
    pub fn new() -> Self {
        let mut points = [k256::AffinePoint::IDENTITY; 256];
        for j in 0..255 {
            points[j + 1] = (k256::ProjectivePoint::GENERATOR + &points[j]).to_affine();
        }

        let mut table = [points; 32];
        for i in 1..table.len() {
            for j in 0..256 {
                let mut acc = k256::ProjectivePoint::from(table[i - 1][j]);

                for _ in 0..8 {
                    acc = acc.double();
                }

                table[i][j] = acc.to_affine();
            }
        }

        Self { table }
    }

    pub fn mul(&self, scalar: &k256::Scalar) -> k256::ProjectivePoint {
        let bytes: [u8; 32] = scalar.to_bytes().into();
        let mut accum = k256::ProjectivePoint::from(self.table[0][bytes[0] as usize]);
        for i in 1..32 {
            accum += self.table[i][bytes[i] as usize];
        }
        accum
    }

    pub fn mul_rayon(&self, scalar: &k256::Scalar) -> k256::ProjectivePoint {
        use rayon::prelude::*;

        let bytes: [u8; 32] = scalar.to_bytes().into();
        bytes
            .par_iter()
            .enumerate()
            .map(|(i, b)| k256::ProjectivePoint::from(self.table[i][*b as usize]))
            .reduce(|| k256::ProjectivePoint::IDENTITY, |a, b| a + b)
    }
}
