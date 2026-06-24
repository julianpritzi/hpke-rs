use alloc::vec::Vec;

use hpke_rs_crypto::{error::Error, types::KdfAlgorithm, HpkeCrypto};

const HPKE_VERSION: &[u8] = b"HPKE-v1";

#[inline]
fn build_labeled_ikm(suite_id: &[u8], label: &str, ikm: &[u8]) -> Vec<u8> {
    // Extraction patch: build bytes explicitly rather than through slice
    // concatenation helpers. This preserves the RFC-required order:
    // HPKE_VERSION || suite_id || label || ikm.
    let mut labeled_ikm = Vec::with_capacity(
        HPKE_VERSION.len() + suite_id.len() + label.len() + ikm.len(),
    );
    labeled_ikm.extend_from_slice(HPKE_VERSION);
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label.as_bytes());
    labeled_ikm.extend_from_slice(ikm);
    labeled_ikm
}

#[inline]
fn build_labeled_info(
    suite_id: &[u8],
    label: &str,
    info: &[u8],
    len_bytes: [u8; 2],
) -> Vec<u8> {
    // Extraction patch: explicit assembly preserves exact encoding order:
    // I2OSP(L,2) || HPKE_VERSION || suite_id || label || info.
    let mut labeled_info = Vec::with_capacity(
        len_bytes.len() + HPKE_VERSION.len() + suite_id.len() + label.len() + info.len(),
    );
    labeled_info.extend_from_slice(&len_bytes);
    labeled_info.extend_from_slice(HPKE_VERSION);
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label.as_bytes());
    labeled_info.extend_from_slice(info);
    labeled_info
}

pub(crate) fn labeled_extract<Crypto: HpkeCrypto>(
    alg: KdfAlgorithm,
    salt: &[u8],
    suite_id: &[u8],
    label: &str,
    ikm: &[u8],
) -> Result<Vec<u8>, Error> {
    // Behavior-equivalent to previous concat-based implementation.
    let labeled_ikm = build_labeled_ikm(suite_id, label, ikm);
    Crypto::kdf_extract(alg, salt, &labeled_ikm)
}

pub(crate) fn labeled_expand<Crypto: HpkeCrypto>(
    alg: KdfAlgorithm,
    prk: &[u8],
    suite_id: &[u8],
    // '&str' instead of '&static str' is strictly more general and preserves
    // behavior for existing literal-call sites while reducing extraction
    // type-pressure in Aeneas.
    label: &str,
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, Error> {
    if len > u16::MAX.into() {
        return Err(Error::HpkeInvalidOutputLength);
    }

    let len_bytes = (len as u16).to_be_bytes();
    // Behavior-equivalent to previous concat-based implementation.
    let labeled_info = build_labeled_info(suite_id, label, info, len_bytes);
    Crypto::kdf_expand(alg, prk, &labeled_info, len)
}
