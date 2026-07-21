package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

func caDir() string {
	if v := os.Getenv("NX_CA_DIR"); v != "" {
		return v
	}
	return "/data"
}

// loadCA lit la CA Nextendo (identique a nx-dauth). Renvoie une erreur si elle n'est pas montee.
func loadCA(dir string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(dir + "/ca.pem")
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(dir + "/ca.key")
	if err != nil {
		return nil, nil, err
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, nil, fmt.Errorf("ca.pem invalide")
	}
	caCert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, fmt.Errorf("ca.key invalide")
	}
	if k, e := x509.ParsePKCS8PrivateKey(kb.Bytes); e == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return caCert, rk, nil
		}
	}
	if rk, e := x509.ParsePKCS1PrivateKey(kb.Bytes); e == nil {
		return caCert, rk, nil
	}
	return nil, nil, fmt.Errorf("ca.key : format de cle non reconnu")
}

// Cert des 4 hosts scsi, SIGNE par la CA Nextendo.
//
// Il etait auto-signe, en pariant que disable_ca_verification desactive toute verification cote
// console — "n'importe quel cert passe". Ce pari est faux pour une partie des consoles : mesure du
// 2026-07-17, elles rejettent notre TLS ("unknown certificate authority") et remontent 2123-0011,
// alors que d'autres, sur le MEME hote et le MEME cert, passent sans probleme. Les patches
// disable_ca_verification sont filtres par build-id de firmware : une console hors de la liste
// couverte verifie donc bel et bien les certificats.
//
// Signer avec la CA Nextendo (celle que Prelude installe) rend le cert valide pour les DEUX
// populations : verification active -> la chaine remonte a une CA de confiance ; verification
// desactivee -> ca passait deja. Repli auto-signe si la CA n'est pas montee, pour ne jamais
// empecher le service de demarrer.
func selfSignedCert() tls.Certificate {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "storage.hac.lp1.scsi.srv.nintendo.net", Organization: []string{"Nextendo"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{
			"storage.hac.lp1.scsi.srv.nintendo.net",
			"scsi-download.lp1.scsi.srv.nintendo.net",
			"scsi-upload.lp1.scsi.srv.nintendo.net",
			"policy.hac.lp1.scsi.srv.nintendo.net",
		},
	}

	if caCert, caKey, err := loadCA(caDir()); err == nil {
		// La cle du serveur reste ECDSA ; c'est la CA (RSA) qui signe.
		if der, e := x509.CreateCertificate(rand.Reader, &tmpl, caCert, &priv.PublicKey, caKey); e == nil {
			keyDER, _ := x509.MarshalECPrivateKey(priv)
			certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			chainPEM := append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})...)
			keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
			if cert, e2 := tls.X509KeyPair(chainPEM, keyPEM); e2 == nil {
				log.Printf("[nx-scsi] cert serveur signé par la CA Nextendo ✓")
				return cert
			}
		}
	}

	log.Printf("[nx-scsi] cert serveur AUTO-SIGNÉ (CA Nextendo absente) — dépend de disable_ca_verification")
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	return cert
}
