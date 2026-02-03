use p3_field::Field;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DensePolynomial<F: Field> {
    pub coeffs: Vec<F>,
}

impl<F: Field> DensePolynomial<F> {
    #[must_use]
    pub const fn from_coefficients_vec(coeffs: Vec<F>) -> Self {
        Self { coeffs }
    }

    #[must_use]
    pub fn evaluate(&self, x: F) -> F {
        self.coeffs
            .iter()
            .rev()
            .fold(F::ZERO, |acc, coeff| acc * x + *coeff)
    }

    #[must_use]
    pub fn evaluate_extension<EF>(&self, x: EF) -> EF
    where
        EF: p3_field::ExtensionField<F>,
    {
        self.coeffs
            .iter()
            .rev()
            .fold(EF::ZERO, |acc, coeff| acc * x + EF::from(*coeff))
    }

    pub fn mul_assign(&mut self, other: &Self) {
        if self.coeffs.is_empty() || other.coeffs.is_empty() {
            self.coeffs.clear();
            return;
        }

        let mut out = vec![F::ZERO; self.coeffs.len() + other.coeffs.len() - 1];
        for (i, &a) in self.coeffs.iter().enumerate() {
            for (j, &b) in other.coeffs.iter().enumerate() {
                out[i + j] += a * b;
            }
        }
        self.coeffs = out;
    }

    #[must_use]
    pub fn lagrange_interpolation<Base>(points: &[(Base, F)]) -> Option<Self>
    where
        Base: Field,
        F: From<Base>,
    {
        if points.is_empty() {
            return Some(Self { coeffs: vec![] });
        }

        let n = points.len();
        let mut result = vec![F::ZERO; n];

        for (i, (x_i, y_i)) in points.iter().copied().enumerate() {
            let mut denom = Base::ONE;
            let mut basis = vec![F::ONE];

            for (j, (x_j, _)) in points.iter().copied().enumerate() {
                if i == j {
                    continue;
                }
                denom *= x_i - x_j;

                let xj = F::from(x_j);
                let mut next = vec![F::ZERO; basis.len() + 1];
                for (k, &coeff) in basis.iter().enumerate() {
                    next[k] += coeff * (-xj);
                    next[k + 1] += coeff;
                }
                basis = next;
            }

            let denom_inv = denom.inverse();
            let scale = y_i * F::from(denom_inv);
            for (k, coeff) in basis.iter().enumerate() {
                result[k] += *coeff * scale;
            }
        }

        Some(Self { coeffs: result })
    }
}
