package metricsserver

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
)

const (
	caFile   = "ca.pem"
	certFile = "cert.pem"
	keyFile  = "key.pem"
	caKeyPem = "ca-key.pem"
)

// TestServePrometheusMetricsHTTPS tests the ServePrometheusMetricsHTTPS function.
func TestServePrometheusMetricsHTTPS(t *testing.T) {
	RegisterTestingT(t)
	host := "127.0.0.1"
	port := 9091
	tempDir := t.TempDir()

	serverCertsDir := filepath.Join(tempDir, "server")

	// Generate CA certificate and key
	ca, caKey, err := GenerateTestCA(serverCertsDir)
	require.NoError(t, err, "Failed to generate test certificates")

	// Generate server certificate and key
	err = generateTestCertificateAndKey(serverCertsDir, ca, caKey, net.ParseIP(host))
	require.NoError(t, err, "Failed to generate test certificates")

	serverCert := filepath.Join(serverCertsDir, certFile)
	serverKey := filepath.Join(serverCertsDir, keyFile)
	serverCA := filepath.Join(serverCertsDir, caFile)

	// Start the HTTPS metrics server in a goroutine
	go ServePrometheusMetricsHTTPS(host, port, serverCert, serverKey, serverCA)

	// Wait for the server to start
	time.Sleep(5 * time.Second)

	// Prepare test cases
	for _, test := range []struct {
		name           string
		dir            string
		clientCertIp   string
		ca             *x509.Certificate
		caKey          *rsa.PrivateKey
		caLocation     string
		expectedStatus int
		expectError    bool
	}{
		{
			name:           "Valid client certificates",
			dir:            filepath.Join(tempDir, "validClient"),
			clientCertIp:   host,
			ca:             ca,
			caKey:          caKey,
			caLocation:     serverCertsDir,
			expectedStatus: 200,
			expectError:    false,
		},
		{
			name:         "Empty client certificates",
			dir:          "",
			clientCertIp: host,
			ca:           ca,
			caKey:        caKey,
			caLocation:   serverCertsDir,
			expectError:  true,
		},
		{
			name:           "Different host ip in client certificates",
			dir:            filepath.Join(tempDir, "wrongHostClient"),
			clientCertIp:   "192.168.1.1",
			ca:             ca,
			caKey:          caKey,
			caLocation:     serverCertsDir,
			expectedStatus: 200,
		},
		{
			name:         "Client has wrong CA cert certificates",
			dir:          filepath.Join(tempDir, "wrongCACertClient"),
			clientCertIp: host,
			caLocation:   "",
			expectError:  true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			RegisterTestingT(t)
			if test.dir != "" {
				// Create test directory
				err := os.MkdirAll(test.dir, 0755)
				require.NoError(t, err, "Failed to create test directory")

				if test.ca == nil || test.caKey == nil {
					// Generate CA certificate and key if not provided
					ca, caKey, err = GenerateTestCA(test.dir)
					require.NoError(t, err, "Failed to generate test certificates")
				}

				if test.caLocation != "" {
					// Copy CA certificate to test directory
					caCertBytes, err := os.ReadFile(filepath.Join(test.caLocation, caFile))
					require.NoError(t, err, "Failed to read CA certificate")
					caCertKeyBytes, err := os.ReadFile(filepath.Join(test.caLocation, caKeyPem))
					require.NoError(t, err, "Failed to read CA private key")
					err = os.WriteFile(filepath.Join(test.dir, caFile), caCertBytes, 0644)
					require.NoError(t, err, "Failed to write CA certificate")
					err = os.WriteFile(filepath.Join(test.dir, caKeyPem), caCertKeyBytes, 0644)
					require.NoError(t, err, "Failed to write CA private key")

					ca = test.ca
					caKey = test.caKey
				}

				// Generate client certificate and key
				err = generateTestCertificateAndKey(test.dir, ca, caKey, net.ParseIP(test.clientCertIp))
				require.NoError(t, err, "Failed to generate test certificates")
			}

			// Load CA certificate
			caCertPool := x509.NewCertPool()

			client := &http.Client{}
			if test.dir != "" {
				caCertBytes, err := os.ReadFile(filepath.Join(test.dir, caFile))
				caCertPool.AppendCertsFromPEM(caCertBytes)

				clientCert, err := tls.LoadX509KeyPair(
					filepath.Join(test.dir, certFile),
					filepath.Join(test.dir, keyFile),
				)
				Expect(err).NotTo(HaveOccurred())

				client = &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							Certificates: []tls.Certificate{clientCert}, // Add client cert
							RootCAs:      caCertPool,
						},
					},
				}
			}

			// Make request to metrics endpoint
			resp, err := client.Get(fmt.Sprintf("https://%s:%d/metrics", host, port))
			if test.expectError {
				Expect(err).To(HaveOccurred())
				return
			}

			defer resp.Body.Close()
			Expect(resp.StatusCode).To(Equal(test.expectedStatus))
		})
	}
}

// TestServePrometheusMetricsHTTPS_CertRotation tests the certificate rotation functionality.
func TestServePrometheusMetricsHTTPS_CertRotation(t *testing.T) {
	RegisterTestingT(t)
	host := "127.0.0.1"
	port := 9092
	tempDir := t.TempDir()

	serverCertsDir := filepath.Join(tempDir, "server")
	clientCertDir := filepath.Join(tempDir, "client")

	// Generate initial CA and server certificate
	ca, caKey, err := GenerateTestCA(serverCertsDir)
	require.NoError(t, err, "Failed to generate test CA")

	err = generateTestCertificateAndKey(serverCertsDir, ca, caKey, net.ParseIP(host))
	require.NoError(t, err, "Failed to generate initial server certificate")

	err = generateTestCertificateAndKey(clientCertDir, ca, caKey, net.ParseIP(host))
	require.NoError(t, err, "Failed to generate initial client certificate")

	serverCert := filepath.Join(serverCertsDir, certFile)
	serverKey := filepath.Join(serverCertsDir, keyFile)
	serverCA := filepath.Join(serverCertsDir, caFile)

	// Start the HTTPS server in a goroutine
	go ServePrometheusMetricsHTTPS(host, port, serverCert, serverKey, serverCA)

	// Wait for the server to start
	time.Sleep(3 * time.Second)

	// Create a client using the initial CA certificate
	caCertPool := x509.NewCertPool()
	caCertBytes, err := os.ReadFile(serverCA)
	require.NoError(t, err, "Failed to read CA certificate")
	caCertPool.AppendCertsFromPEM(caCertBytes)

	clientCert, err := tls.LoadX509KeyPair(
		filepath.Join(clientCertDir, certFile),
		filepath.Join(clientCertDir, keyFile),
	)
	Expect(err).NotTo(HaveOccurred())

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert}, // Add client cert
				RootCAs:      caCertPool,
			},
		},
	}

	// Verify that the initial certificate works
	resp, err := client.Get(fmt.Sprintf("https://%s:%d/metrics", host, port))
	require.NoError(t, err, "Initial certificate validation failed")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Generate a new server certificate
	err = generateTestCertificateAndKey(serverCertsDir, ca, caKey, net.ParseIP(host))
	require.NoError(t, err, "Failed to generate new server certificate")

	// Generate a new client certificate
	err = generateTestCertificateAndKey(clientCertDir, ca, caKey, net.ParseIP(host))
	require.NoError(t, err, "Failed to generate new client certificate")

	// Create a client using the initial CA certificate
	caCertBytes, err = os.ReadFile(serverCA)
	require.NoError(t, err, "Failed to read CA certificate")
	caCertPool.AppendCertsFromPEM(caCertBytes)

	clientCert, err = tls.LoadX509KeyPair(
		filepath.Join(clientCertDir, certFile),
		filepath.Join(clientCertDir, keyFile),
	)
	Expect(err).NotTo(HaveOccurred())

	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert}, // Add client cert
				RootCAs:      caCertPool,
			},
		},
	}

	// Verify that the server now accepts the new certificate
	resp, err = client.Get(fmt.Sprintf("https://%s:%d/metrics", host, port))
	require.NoError(t, err, "Failed after certificate rotation")
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// GenerateTestCA generates a test CA certificate and private key.
func GenerateTestCA(dir string) (*x509.Certificate, *rsa.PrivateKey, error) {
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return nil, nil, err
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2025),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
			Locality:     []string{"Test City"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	if err := os.WriteFile(filepath.Join(dir, caFile), caPEM.Bytes(), 0644); err != nil {
		return nil, nil, err
	}

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	if err := os.WriteFile(filepath.Join(dir, caKeyPem), caPrivKeyPEM.Bytes(), 0644); err != nil {
		return nil, nil, err
	}

	return ca, caPrivKey, nil
}

// generateTestCertificateAndKey generates a test certificate and private key signed by the given CA.
func generateTestCertificateAndKey(dir string, ca *x509.Certificate, caPrivKey *rsa.PrivateKey, ip net.IP) error {
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return err
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
			Locality:     []string{"Test City"},
		},
		IPAddresses:  []net.IP{ip},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	if err := os.WriteFile(filepath.Join(dir, certFile), certPEM.Bytes(), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, keyFile), certPrivKeyPEM.Bytes(), 0644); err != nil {
		return err
	}

	return nil
}
