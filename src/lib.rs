use bincode::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};

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

/// An implementation of the Hash Commitment Scheme using the SHA256 hash function.
///
/// We store the party's secret and random number as references because we don't want to take
/// ownership over those variables and avoid useless copies (we only perform read operations
/// with them).
///
/// We use lifetime annotations as we need to store references to existing variables in our
/// structure, so that an instance of SHA256Commitment can not outlive the references
/// it holds.
pub struct SHA256Commitment<'a, T: 'a + Serialize> {
    s: &'a T,
    r: &'a [u8],
}

impl<'a, T: 'a + Serialize> SHA256Commitment<'a, T> {
    /// Creates a new party for the SHA256 Commitment Scheme using its secret and random
    /// number.
    pub fn new(s: &'a T, r: &'a [u8]) -> SHA256Commitment<'a, T> {
        SHA256Commitment { s, r }
    }

    /// Forges a commitment given a secret s and a random number r.
    ///
    /// We encode the secret to a byte array (which is padded by default), and use it along with
    /// the random number, given as a byte array, to forge the commitment using the SHA256 hash
    /// function.
    fn forge_commitment(&self, s: &T, r: &[u8]) -> Result<Vec<u8>> {
        let binary_encoded_s = bincode::serialize(s)?;

        let hash = Sha256::new()
            .chain_update(binary_encoded_s.as_slice())
            .chain_update(r)
            .finalize();

        Ok(hash.as_slice().to_vec())
    }
}

impl<'a, T: 'a + Serialize> HashCommitmentScheme<T> for SHA256Commitment<'a, T> {
    /// Creates the commitment used during the commit phase.
    fn commit(&self) -> Result<Vec<u8>> {
        self.forge_commitment(self.s, self.r)
    }

    /// Creates the expected commitment using the prover's secret and random number.
    /// Then, compares the expected commitment with the prover's one to verify if the commitment
    /// holds.
    fn verify(&self, com: &[u8], s: &T, r: &[u8]) -> Result<bool> {
        let expected_commitment = self.forge_commitment(s, r)?;

        Ok(expected_commitment == com)
    }
}

#[cfg(test)]
mod tests {
    use super::{HashCommitmentScheme, SHA256Commitment};
    use hex_literal::hex;

    #[test]
    fn it_commits_correctly() {
        let s: [u8; 4] = [52, 50, 52, 50]; // 4242 in string format.
        let r: [u8; 4] = [50, 52, 50, 52]; // 2424 in string format.

        let party = SHA256Commitment::new(&s, &r);
        let commit = party.commit();

        assert_eq!(commit.is_ok(), true);
        assert_eq!(
            commit.unwrap().as_slice(),
            hex!("f4417d2878a0e2da0393e604b24a98627fd22506089baa83c165f9ac7b336fe9")
        )
    }

    /// Here, one party acts as both the prover and the verifier,
    /// assuming that the verifier is not malicious.
    #[test]
    fn it_verifies_valid_commitment() {
        let s: [u8; 4] = [52, 50, 52, 50]; // 4242 in string format.
        let r: [u8; 4] = [50, 52, 50, 52]; // 2424 in string format.

        // Commit phase.
        let party = SHA256Commitment::new(&s, &r);
        let commit = party.commit();

        // Verification phase.
        let verification = party.verify(&commit.unwrap(), &s, &r);

        assert_eq!(verification.is_ok(), true);
        assert_eq!(verification.unwrap(), true)
    }

    /// Here, during the verification phase, we assume that the prover has given an invalid r.
    #[test]
    fn it_fails_to_verify_due_to_invalid_random() {
        let s: [u8; 4] = [52, 50, 52, 50]; // 4242 in string format.
        let r: [u8; 4] = [50, 52, 50, 52]; // 2424 in string format.

        // Commit phase.
        let party = SHA256Commitment::new(&s, &r);
        let commit = party.commit();

        // Verification phase.
        let fake_r: [u8; 4] = [66, 68, 66, 68];
        let verification = party.verify(&commit.unwrap(), &s, &fake_r);

        assert_eq!(verification.is_ok(), true);
        assert_eq!(verification.unwrap(), false)
    }

    /// Here, during the verification phase, we assume that the prover has given an invalid secret.
    /// This happens when the prover decides to break his initial commitment.
    #[test]
    fn it_fails_to_verify_due_to_invalid_secret() {
        let s: [u8; 4] = [52, 50, 52, 50]; // 4242 in string format.
        let r: [u8; 4] = [50, 52, 50, 52]; // 2424 in string format.

        // Commit phase.
        let party = SHA256Commitment::new(&s, &r);
        let commit = party.commit();

        // Verification phase.
        let fake_s: [u8; 4] = [66, 68, 66, 68];
        let verification = party.verify(&commit.unwrap(), &fake_s, &r);

        assert_eq!(verification.is_ok(), true);
        assert_eq!(verification.unwrap(), false)
    }
}
