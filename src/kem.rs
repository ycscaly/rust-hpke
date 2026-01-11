//! Traits and structs for key encapsulation mechanisms

use crate::{Deserializable, HpkeError, Serializable};

use core::fmt::Debug;

use hybrid_array::{Array, ArraySize};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

mod dhkem;
pub use dhkem::*;

/// Represents authenticated encryption functionality
pub trait Kem: Sized {
    /// The key exchange's public key type. If you want to generate a keypair, see
    /// `Kem::gen_keypair` or `Kem::derive_keypair`
    type PublicKey: Clone + Debug + PartialEq + Eq + Serializable + Deserializable;

    /// The key exchange's private key type. If you want to generate a keypair, see
    /// `Kem::gen_keypair` or `Kem::derive_keypair`
    type PrivateKey: Clone + PartialEq + Eq + Serializable + Deserializable;

    /// Computes the public key of a given private key
    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey;
    /// The encapsulated key for this KEM. This is used by the recipient to derive the shared
    /// secret.
    type EncappedKey: Clone + Serializable + Deserializable;

    /// The size of a shared secret in this KEM
    #[doc(hidden)]
    type NSecret: ArraySize;

    /// The algorithm identifier for a KEM implementation
    const KEM_ID: u16;

    /// Deterministically derives a keypair from the given input keying material
    ///
    /// Requirements
    /// ============
    /// This keying material SHOULD have as many bits of entropy as the bit length of a secret key,
    /// i.e., `8 * Self::PrivateKey::size()`. For X25519 and P-256, this is 256 bits of
    /// entropy.
    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey);

    /// Generates a random keypair using the given RNG
    fn gen_keypair<R: CryptoRng + RngCore>(csprng: &mut R) -> (Self::PrivateKey, Self::PublicKey) {
        // Make some keying material that's the size of a private key
        let mut ikm: Array<u8, <Self::PrivateKey as Serializable>::OutputSize> = Array::default();
        // Fill it with randomness
        csprng.fill_bytes(&mut ikm);
        // Run derive_keypair using the KEM's KDF
        Self::derive_keypair(&ikm)
    }

    /// Derives a shared secret given the encapsulated key and the recipients secret key. If
    /// `pk_sender_id` is given, the sender's identity will be tied to the shared secret.
    ///
    /// Return Value
    /// ============
    /// Returns a shared secret on success. If an error happened during key exchange, returns
    /// `Err(HpkeError::DecapError)`.
    #[doc(hidden)]
    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError>;

    /// Derives a shared secret and an ephemeral pubkey that the owner of the reciepint's pubkey
    /// can use to derive the same shared secret. If `sk_sender_id` is given, the sender's identity
    /// will be tied to the shared secret. All this does is generate an ephemeral keypair and pass
    /// to `encap_with_eph`.
    ///
    /// Return Value
    /// ============
    /// Returns a shared secret and encapped key on success. If an error happened during key
    /// exchange, returns `Err(HpkeError::EncapError)`.
    #[doc(hidden)]
    fn encap<R: CryptoRng + RngCore>(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut R,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError>;
}

// Kem is used as a type parameter everywhere. To avoid confusion, alias it
use Kem as KemTrait;

/// A convenience type for `[u8; NSecret]` for any given KEM
#[doc(hidden)]
pub struct SharedSecret<Kem: KemTrait>(pub Array<u8, Kem::NSecret>);

impl<Kem: KemTrait> Default for SharedSecret<Kem> {
    fn default() -> SharedSecret<Kem> {
        SharedSecret(Array::<u8, Kem::NSecret>::default())
    }
}

impl<Kem: KemTrait> SharedSecret<Kem> {
    /// Creates a `SharedSecret` from raw bytes.
    ///
    /// This is useful when you have computed the shared secret externally (e.g., via a custom
    /// key exchange) and want to use it with the HPKE key schedule.
    ///
    /// # Security
    /// This function validates that the input is not all zeros, as required by RFC 9180 §7.1.4
    /// for X25519 and X448 to prevent small-subgroup attacks.
    ///
    /// # Errors
    /// - `Err(HpkeError::IncorrectInputLength)` if the input length doesn't match `Kem::NSecret`
    /// - `Err(HpkeError::ValidationError)` if the input is all zeros (invalid DH result)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HpkeError> {
        if bytes.len() != <Kem::NSecret as hybrid_array::typenum::Unsigned>::USIZE {
            return Err(HpkeError::IncorrectInputLength(
                <Kem::NSecret as hybrid_array::typenum::Unsigned>::USIZE,
                bytes.len(),
            ));
        }

        // RFC 9180 §7.1.4: "For X25519 and X448, the small-subgroup attack can be avoided
        // by checking that the DH shared secret is not the all-zero value after computing it."
        // We apply this check to all KEMs for defense in depth.
        if bytes.iter().all(|&b| b == 0) {
            return Err(HpkeError::ValidationError);
        }

        let mut arr = Array::<u8, Kem::NSecret>::default();
        arr.copy_from_slice(bytes);
        Ok(SharedSecret(arr))
    }
}

// SharedSecrets should zeroize on drop
impl<Kem: KemTrait> Zeroize for SharedSecret<Kem> {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}
impl<Kem: KemTrait> Drop for SharedSecret<Kem> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use crate::{kem::Kem as KemTrait, Deserializable, HpkeError, Serializable};

    #[cfg(feature = "x25519")]
    #[test]
    fn test_shared_secret_rejects_all_zeros() {
        use super::SharedSecret;
        use crate::kem::X25519HkdfSha256;

        // All-zero bytes should be rejected per RFC 9180 §7.1.4
        let zero_bytes = [0u8; 32];
        let result = SharedSecret::<X25519HkdfSha256>::from_bytes(&zero_bytes);

        assert!(
            matches!(result, Err(HpkeError::ValidationError)),
            "All-zero shared secret should be rejected with ValidationError"
        );
    }

    #[cfg(feature = "x25519")]
    #[test]
    fn test_shared_secret_accepts_non_zero() {
        use super::SharedSecret;
        use crate::kem::X25519HkdfSha256;

        // Non-zero bytes should be accepted
        let mut bytes = [0u8; 32];
        bytes[0] = 1; // At least one non-zero byte
        let result = SharedSecret::<X25519HkdfSha256>::from_bytes(&bytes);

        assert!(result.is_ok(), "Non-zero shared secret should be accepted");
    }

    macro_rules! test_encap_correctness {
        ($test_name:ident, $kem_ty:ty) => {
            /// Tests that encap and decap produce the same shared secret when composed
            #[test]
            fn $test_name() {
                type Kem = $kem_ty;

                let mut csprng = rand::rng();
                let (sk_recip, pk_recip) = Kem::gen_keypair(&mut csprng);

                // Encapsulate a random shared secret
                let (auth_shared_secret, encapped_key) =
                    Kem::encap(&pk_recip, None, &mut csprng).unwrap();

                // Decap it
                let decapped_auth_shared_secret =
                    Kem::decap(&sk_recip, None, &encapped_key).unwrap();

                // Ensure that the encapsulated secret is what decap() derives
                assert_eq!(auth_shared_secret.0, decapped_auth_shared_secret.0);

                //
                // Now do it with the auth, i.e., using the sender's identity keys
                //

                // Make a sender identity keypair
                let (sk_sender_id, pk_sender_id) = Kem::gen_keypair(&mut csprng);

                // Encapsulate a random shared secret
                let (auth_shared_secret, encapped_key) = Kem::encap(
                    &pk_recip,
                    Some((&sk_sender_id, &pk_sender_id.clone())),
                    &mut csprng,
                )
                .unwrap();

                // Decap it
                let decapped_auth_shared_secret =
                    Kem::decap(&sk_recip, Some(&pk_sender_id), &encapped_key).unwrap();

                // Ensure that the encapsulated secret is what decap() derives
                assert_eq!(auth_shared_secret.0, decapped_auth_shared_secret.0);
            }
        };
    }

    /// Tests that an deserialize-serialize round trip on an encapped key ends up at the same value
    macro_rules! test_encapped_serialize {
        ($test_name:ident, $kem_ty:ty) => {
            #[test]
            fn $test_name() {
                type Kem = $kem_ty;

                // Encapsulate a random shared secret
                let encapped_key = {
                    let mut csprng = rand::rng();
                    let (_, pk_recip) = Kem::gen_keypair(&mut csprng);
                    Kem::encap(&pk_recip, None, &mut csprng).unwrap().1
                };
                // Serialize it
                let encapped_key_bytes = encapped_key.to_bytes();
                // Deserialize it
                let new_encapped_key =
                    <<Kem as KemTrait>::EncappedKey as Deserializable>::from_bytes(
                        &encapped_key_bytes,
                    )
                    .unwrap();

                assert_eq!(
                    new_encapped_key.0, encapped_key.0,
                    "encapped key doesn't serialize correctly"
                );
            }
        };
    }

    #[cfg(feature = "x25519")]
    mod x25519_tests {
        use super::*;

        test_encap_correctness!(test_encap_correctness_x25519, crate::kem::X25519HkdfSha256);
        test_encapped_serialize!(test_encapped_serialize_x25519, crate::kem::X25519HkdfSha256);
    }

    #[cfg(feature = "p256")]
    mod p256_tests {
        use super::*;

        test_encap_correctness!(test_encap_correctness_p256, crate::kem::DhP256HkdfSha256);
        test_encapped_serialize!(test_encapped_serialize_p256, crate::kem::DhP256HkdfSha256);
    }

    #[cfg(feature = "p384")]
    mod p384_tests {
        use super::*;

        test_encap_correctness!(test_encap_correctness_p384, crate::kem::DhP384HkdfSha384);
        test_encapped_serialize!(test_encapped_serialize_p384, crate::kem::DhP384HkdfSha384);
    }

    #[cfg(feature = "p521")]
    mod p521_tests {
        use super::*;

        test_encap_correctness!(test_encap_correctness_p521, crate::kem::DhP521HkdfSha512);
        test_encapped_serialize!(test_encapped_serialize_p521, crate::kem::DhP521HkdfSha512);
    }
}
