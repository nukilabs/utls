package tls

// clientSupportedSignatureAlgorithms returns the signature algorithms a client
// accepts in the server's CertificateVerify message.
//
// It adds the ML-DSA schemes to supportedSignatureAlgorithms for TLS 1.3 only,
// because the ML-DSA codepoints (RFC 9881) are defined for TLS 1.3 only.
//
// The client does not advertise these schemes in a default ClientHello. Only a
// profile that carries the ML-DSA codepoints in its own signature_algorithms
// extension offers them. The bytes of a default ClientHello, and therefore the
// fingerprint of HelloGolang, do not change.
//
// The server call sites keep using supportedSignatureAlgorithms, so a uTLS
// server neither advertises the ML-DSA codepoints in its CertificateRequest nor
// accepts an ML-DSA client certificate.
//
// Go 1.27 crypto/tls does this differently: it advertises ML-DSA in the default
// ClientHello and filters the schemes out again in isDisabledSignatureAlgorithm.
// The base of this fork is older and has no such function.
func clientSupportedSignatureAlgorithms(vers uint16) []SignatureScheme {
	shared := supportedSignatureAlgorithms()
	if vers < VersionTLS13 {
		return shared
	}

	// Build a new slice. Appending to shared could write into the array behind
	// defaultSupportedSignatureAlgorithms, which the server call sites read.
	algorithms := make([]SignatureScheme, 0, len(shared)+3)
	algorithms = append(algorithms, MLDSA44, MLDSA65, MLDSA87)
	return append(algorithms, shared...)
}
