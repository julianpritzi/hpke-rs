use alloc::vec::Vec;

#[inline]
pub(crate) fn concat(values: &[&[u8]]) -> Vec<u8> {
    values.join(&[][..])
}

#[inline]
pub(crate) fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    // Extraction patch: this is equivalent to
    // a.iter().zip(b).map(|(x, y)| x ^ y).collect()
    // but avoids iterator-adapter lowering that caused Aeneas issues.
    // For each i in [0, len), output[i] = a[i] XOR b[i].
    let mut out = Vec::with_capacity(a.len());
    for i in 0..a.len() {
        out.push(a[i] ^ b[i]);
    }
    out
}

#[test]
fn test_concat() {
    let a = "blabla";
    let b = "RFCXXXX ";
    let expected = "blablaRFCXXXX ";
    assert_eq!(
        expected.as_bytes()[..],
        concat(&[a.as_bytes(), b.as_bytes()])[..]
    )
}
