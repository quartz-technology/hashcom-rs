use bincode::Result;
use serde::Serialize;

/// A high-level representation of a party in a Hash Commitment Scheme.
///
/// ### Commit Phase
/// During the commit phase, the prover hides the secret denoted as s using a random number r.
/// Each implementation of this trait is responsible for the usage of a dedicated hash function.
/// Once the commitment has been built, the prover sends it to the verifier.
///
/// ### Open Phase
/// During the open phase, the prover reveals his secret s and the random number r he choose to
/// forge the commitment.
///
/// ### Verification Phase
/// During this last phase, the verifier uses the prover's secret and random number
/// to forge the expected commitment. If the prover's initial commitment differs from the
/// expected one, the commitment has not been fulfilled by the prover.
pub trait HashCommitmentScheme<T: Serialize> {
    fn commit(&self) -> Result<Vec<u8>>;
    fn verify(&self, com: &[u8], s: &T, r: &[u8]) -> Result<bool>;
}