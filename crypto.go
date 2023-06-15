package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"time"
)

func generateCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		Version:               3,
		SerialNumber:          big.NewInt(1),
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

func generateCert(servername string, parent *x509.Certificate, priv *ecdsa.PrivateKey) (*x509.Certificate, ed25519.PrivateKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(2),
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
		DNSNames:     []string{servername},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, caTemplate, parent, pubKey, priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	return cert, privKey, err
}
