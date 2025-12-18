pub enum Kem {
    /// KEM using DHKEM P-256 and HKDF-SHA256.
    P256HkdfSha256 = 16, // 0x0010
    /// KEM using DHKEM X25519 and HKDF-SHA256.
    X25519HkdfSha256 = 32, // 0x0020
    /// X-Wing hybrid KEM.
    XWing = 25722, // 0x647a
    /// ML-KEM-768.
    MlKem768 = 65, // 0x0041
    /// ML-KEM-1024.
    MlKem1024 = 66, // 0x0042
}