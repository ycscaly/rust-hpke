use crate::{
    dhkex::{DhError, DhKeyExchange},
    kdf::{labeled_extract, Kdf as KdfTrait, LabeledExpand},
    util::{enforce_equal_len, KemSuiteId},
    Deserializable, HpkeError, Serializable,
};

use generic_array::{
    typenum::{self, Unsigned},
    GenericArray,
};
use subtle::ConstantTimeEq;

// We wrap the types in order to abstract away the dalek dep

/// An X25519 public key
#[derive(Clone)]
pub struct PublicKey(x25519_dalek::PublicKey);

// The underlying type is zeroize-on-drop
/// An X25519 private key
#[derive(Clone)]
pub struct PrivateKey(x25519_dalek::StaticSecret);

// The underlying type is zeroize-on-drop
/// A bare DH computation result
pub struct KexResult(x25519_dalek::SharedSecret);

// Oh I love an excuse to break out type-level integers
impl Serializable for PublicKey {
    // RFC 9180 §7.1 Table 2: Npk of DHKEM(X25519, HKDF-SHA256) is 32
    type OutputSize = typenum::U32;

    // Dalek lets us convert pubkeys to [u8; 32]
    fn to_bytes(&self) -> GenericArray<u8, typenum::U32> {
        GenericArray::clone_from_slice(self.0.as_bytes())
    }
}

impl Deserializable for PublicKey {
    // Dalek lets us convert [u8; 32] to pubkeys. Assuming the input length is correct, this
    // conversion is infallible, so no ValidationErrors are raised.
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        // Pubkeys must be 32 bytes
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        // Copy to a fixed-size array
        let mut arr = [0u8; 32];
        arr.copy_from_slice(encoded);
        Ok(PublicKey(x25519_dalek::PublicKey::from(arr)))
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        write!(f, "PublicKey({:?})", self.0)
    }
}

impl Serializable for PrivateKey {
    // RFC 9180 §7.1 Table 2: Nsk of DHKEM(X25519, HKDF-SHA256) is 32
    type OutputSize = typenum::U32;

    // Dalek lets us convert scalars to [u8; 32]
    fn to_bytes(&self) -> GenericArray<u8, typenum::U32> {
        GenericArray::clone_from_slice(&self.0.to_bytes())
    }
}
impl Deserializable for PrivateKey {
    // Dalek lets us convert [u8; 32] to scalars. Assuming the input length is correct, this
    // conversion is infallible, so no ValidationErrors are raised.
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        // Privkeys must be 32 bytes
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        // Copy to a fixed-size array
        let mut arr = [0u8; 32];
        arr.copy_from_slice(encoded);
        // We don't have to do a zero-check for X25519 private keys. We clamp all private keys upon
        // deserialization, and clamped private keys cannot ever be 0 mod curve_order. In fact,
        // they can't even be 0 mod q where q is the order of the prime subgroup generated by the
        // canonical generator.
        // Why?
        // A clamped key k is of the form 2^254 + 8j where j is in [0, 2^251-1]. If k = 0 (mod q)
        // then k = nq for some n > 0. And since k is a multiple of 8 and q is prime, n must be a
        // multiple of 8. However, 8q > 2^257 which is already out of representable range! So k
        // cannot be 0 (mod q).
        Ok(PrivateKey(x25519_dalek::StaticSecret::from(arr)))
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &PrivateKey) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Serializable for KexResult {
    // RFC 9180 §4.1: For X25519 and X448, the size Ndh is equal to 32 and 56, respectively
    type OutputSize = typenum::U32;

    // curve25519's point representation is our DH result. We don't have to do anything special.
    fn to_bytes(&self) -> GenericArray<u8, typenum::U32> {
        // Dalek lets us convert shared secrets to to [u8; 32]
        GenericArray::clone_from_slice(self.0.as_bytes())
    }
}

/// Represents ECDH functionality over the X25519 group
pub struct X25519 {}

impl DhKeyExchange for X25519 {
    #[doc(hidden)]
    type PublicKey = PublicKey;
    #[doc(hidden)]
    type PrivateKey = PrivateKey;
    #[doc(hidden)]
    type KexResult = KexResult;

    /// Converts an X25519 private key to a public key
    #[doc(hidden)]
    fn sk_to_pk(sk: &PrivateKey) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(&sk.0))
    }

    /// Does the DH operation. Returns an error if and only if the DH result was all zeros. This is
    /// required by the HPKE spec. The error is converted into the appropriate higher-level error
    /// by the caller, i.e., `HpkeError::EncapError` or `HpkeError::DecapError`.
    #[doc(hidden)]
    fn dh(sk: &PrivateKey, pk: &PublicKey) -> Result<KexResult, DhError> {
        let res = sk.0.diffie_hellman(&pk.0);
        // "Senders and recipients MUST check whether the shared secret is the all-zero value
        // and abort if so"
        if res.as_bytes().ct_eq(&[0u8; 32]).into() {
            Err(DhError)
        } else {
            Ok(KexResult(res))
        }
    }

    // RFC 9180 §7.1.3
    // def DeriveKeyPair(ikm):
    //   dkp_prk = LabeledExtract("", "dkp_prk", ikm)
    //   sk = LabeledExpand(dkp_prk, "sk", "", Nsk)
    //   return (sk, pk(sk))

    /// Deterministically derives a keypair from the given input keying material and ciphersuite
    /// ID. The keying material SHOULD have as many bits of entropy as the bit length of a secret
    /// key, i.e., 256.
    #[doc(hidden)]
    fn derive_keypair<Kdf: KdfTrait>(suite_id: &KemSuiteId, ikm: &[u8]) -> (PrivateKey, PublicKey) {
        // Write the label into a byte buffer and extract from the IKM
        let (_, hkdf_ctx) = labeled_extract::<Kdf>(&[], suite_id, b"dkp_prk", ikm);
        // The buffer we hold the candidate scalar bytes in. This is the size of a private key.
        let mut buf = [0u8; 32];
        hkdf_ctx
            .labeled_expand(suite_id, b"sk", &[], &mut buf)
            .unwrap();

        let sk = x25519_dalek::StaticSecret::from(buf);
        let pk = x25519_dalek::PublicKey::from(&sk);

        (PrivateKey(sk), PublicKey(pk))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        dhkex::{
            x25519::X25519,
            Deserializable, DhKeyExchange, Serializable,
        },
        test_util::dhkex_gen_keypair,
    };
    use generic_array::typenum::Unsigned;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    /// Tests that an serialize-deserialize round-trip ends up at the same pubkey
    #[test]
    fn test_pubkey_serialize_correctness() {
        type Kex = X25519;

        let mut csprng = StdRng::from_entropy();

        // Fill a buffer with randomness
        let orig_bytes = {
            let mut buf =
                [0u8; <<Kex as DhKeyExchange>::PublicKey as Serializable>::OutputSize::USIZE];
            csprng.fill_bytes(buf.as_mut_slice());
            buf
        };

        // Make a pubkey with those random bytes. Note, that from_bytes() does not clamp the input
        // bytes. This is why this test passes.
        let pk = <Kex as DhKeyExchange>::PublicKey::from_bytes(&orig_bytes).unwrap();
        let pk_bytes = pk.to_bytes();

        // See if the re-serialized bytes are the same as the input
        assert_eq!(orig_bytes.as_slice(), pk_bytes.as_slice());
    }

    /// Tests that an deserialize-serialize round trip on a DH keypair ends up at the same values
    #[test]
    fn test_dh_serialize_correctness() {
        type Kex = X25519;

        let mut csprng = StdRng::from_entropy();

        // Make a random keypair and serialize it
        let (sk, pk) = dhkex_gen_keypair::<Kex, _>(&mut csprng);
        let (sk_bytes, pk_bytes) = (sk.to_bytes(), pk.to_bytes());

        // Now deserialize those bytes
        let new_sk = <Kex as DhKeyExchange>::PrivateKey::from_bytes(&sk_bytes).unwrap();
        let new_pk = <Kex as DhKeyExchange>::PublicKey::from_bytes(&pk_bytes).unwrap();

        // See if the deserialized values are the same as the initial ones
        assert!(new_sk == sk, "private key doesn't serialize correctly");
        assert!(new_pk == pk, "public key doesn't serialize correctly");
    }
}
