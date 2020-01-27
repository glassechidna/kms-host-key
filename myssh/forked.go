package myssh

import (
	"crypto"
	"golang.org/x/crypto/ssh"
	"io"
)

func NewSignerFromSigner(input crypto.Signer) (ssh.AlgorithmSigner, error) {
	signer, err := ssh.NewSignerFromSigner(input)
	if err != nil {
		return nil, err
	}

	return signer.(ssh.AlgorithmSigner), nil
}

// forked from golang.org/x/crypto/ssh because we want to use AlgorithSigner instead
// of Signer. this is because Signer will default to SHA-1, which is a) bad and b) unsupported
// by AWS KMS.
func SignCert(c *ssh.Certificate, rand io.Reader, authority ssh.AlgorithmSigner) error {
	c.Nonce = make([]byte, 32)
	if _, err := io.ReadFull(rand, c.Nonce); err != nil {
		return err
	}
	c.SignatureKey = authority.PublicKey()

	sigAlgo := ""
	if c.Key.Type() == ssh.KeyAlgoRSA {
		sigAlgo = ssh.SigAlgoRSASHA2256
	}

	sig, err := authority.SignWithAlgorithm(rand, bytesForSigning(c), sigAlgo)
	if err != nil {
		return err
	}
	c.Signature = sig
	return nil
}

// forked from golang.org/x/crypto/ssh because it's used by the above func
func bytesForSigning(cert *ssh.Certificate) []byte {
	c2 := *cert
	c2.Signature = nil
	out := c2.Marshal()
	// Drop trailing signature length.
	return out[:len(out)-4]
}

