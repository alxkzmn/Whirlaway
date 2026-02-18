use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_field::{ExtensionField, Field};

use whir_p3::fiat_shamir::domain_separator::DomainSeparator;

#[derive(Debug, Clone)]
pub enum ProofError {
    InvalidGrindingWitness,
    NotEnoughProofData,
}

#[derive(Debug, Clone)]
pub struct ProverState<F, EF, Challenger>
where
    F: Field,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    challenger: Challenger,
    proof_data: Vec<EF>,
    _phantom: std::marker::PhantomData<F>,
}

impl<F, EF, Challenger> ProverState<F, EF, Challenger>
where
    F: Field,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    pub fn new(domain_separator: &DomainSeparator<EF, F>, mut challenger: Challenger) -> Self {
        domain_separator.observe_domain_separator(&mut challenger);
        Self {
            challenger,
            proof_data: Vec::new(),
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn add_extension_scalars(&mut self, scalars: &[EF]) {
        self.proof_data.extend_from_slice(scalars);
        self.challenger.observe_algebra_slice(scalars);
    }

    pub const fn challenger_mut(&mut self) -> &mut Challenger {
        &mut self.challenger
    }

    pub fn sample(&mut self) -> EF {
        self.challenger.sample_algebra_element::<EF>()
    }

    pub fn pow_grinding(&mut self, pow_bits: usize) {
        if pow_bits == 0 {
            return;
        }
        let witness = self.challenger.grind(pow_bits);
        self.proof_data.push(EF::from(witness));
    }

    #[must_use]
    pub fn proof_data(&self) -> &[EF] {
        &self.proof_data
    }
}

#[derive(Debug, Clone)]
pub struct VerifierState<F, EF, Challenger>
where
    F: Field,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    challenger: Challenger,
    proof_data: Vec<EF>,
    cursor: usize,
    _phantom: std::marker::PhantomData<F>,
}

impl<F, EF, Challenger> VerifierState<F, EF, Challenger>
where
    F: Field,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    pub fn new(
        domain_separator: &DomainSeparator<EF, F>,
        proof_data: Vec<EF>,
        mut challenger: Challenger,
    ) -> Self {
        domain_separator.observe_domain_separator(&mut challenger);
        Self {
            challenger,
            proof_data,
            cursor: 0,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn next_extension_scalars_vec(&mut self, count: usize) -> Result<Vec<EF>, ProofError> {
        if self.cursor + count > self.proof_data.len() {
            return Err(ProofError::NotEnoughProofData);
        }
        let out = self.proof_data[self.cursor..self.cursor + count].to_vec();
        self.cursor += count;
        self.challenger.observe_algebra_slice(&out);
        Ok(out)
    }

    pub const fn challenger_mut(&mut self) -> &mut Challenger {
        &mut self.challenger
    }

    pub fn sample(&mut self) -> EF {
        self.challenger.sample_algebra_element::<EF>()
    }

    pub fn check_pow_grinding(&mut self, pow_bits: usize) -> Result<(), ProofError> {
        if pow_bits == 0 {
            return Ok(());
        }
        if self.cursor >= self.proof_data.len() {
            return Err(ProofError::NotEnoughProofData);
        }
        let witness_ef = self.proof_data[self.cursor];
        self.cursor += 1;
        let witness = witness_ef
            .as_base()
            .ok_or(ProofError::InvalidGrindingWitness)?;
        if self.challenger.check_witness(pow_bits, witness) {
            Ok(())
        } else {
            Err(ProofError::InvalidGrindingWitness)
        }
    }

    #[must_use]
    pub const fn is_fully_consumed(&self) -> bool {
        self.cursor == self.proof_data.len()
    }

    #[must_use]
    pub const fn remaining_proof_data_len(&self) -> usize {
        self.proof_data.len().saturating_sub(self.cursor)
    }
}
