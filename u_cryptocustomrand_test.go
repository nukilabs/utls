// The reference tests replay recorded transcripts from testdata and compare the bytes
// the client writes against the recorded bytes. That only works if the client derives
// the same ephemeral keys on every run, which the tests arrange by setting
// Config.Rand to a deterministic zeroSource.
//
// Go 1.27 passes the caller's io.Reader through rand.CustomReader in ecdh.GenerateKey
// and friends. By default that function discards the caller's reader and returns the
// system source, so the deterministic reader has no effect and every run produces a
// different key share. The cryptocustomrand=1 setting restores the old behaviour of
// honouring the caller's reader, which makes the transcripts reproducible again.
//
// This directive applies to the test binary of this package only. It does not change
// anything for code that imports this library.
//
//go:debug cryptocustomrand=1

package tls
