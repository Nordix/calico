// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metricsserver

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

func ServePrometheusMetricsHTTP(host string, port int) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	addr := fmt.Sprintf("[%v]:%v", host, port)

	for {
		logrus.WithFields(logrus.Fields{
			"host": host,
			"port": port,
		}).Info("Starting prometheus metrics endpoint")
		err := http.ListenAndServe(addr, mux)
		logrus.WithError(err).Error(
			"Prometheus metrics endpoint failed, trying to restart it...")
		time.Sleep(1 * time.Second)
	}
}

// ServePrometheusMetricsHTTPS starts a secure Prometheus metrics server with dynamic TLS certificate reloading.
func ServePrometheusMetricsHTTPS(host string, port int, certFile string, keyFile string, caFile string) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	addr := fmt.Sprintf("[%v]:%v", host, port)

	// Initial TLS config loading to catch errors early.
	tlsConfig, err := loadTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to load initial TLS configuration")
	}

	// Enable dynamic certificate reloading.
	tlsConfig.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return loadTLSConfig(certFile, keyFile, caFile)
	}

	server := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	// Restart server on failure.
	for {
		logrus.WithFields(logrus.Fields{
			"host": host,
			"port": port,
		}).Info("Starting Prometheus metrics endpoint with TLS")

		err = server.ListenAndServeTLS("", "")
		if err != nil {
			logrus.WithError(err).Error("Prometheus metrics endpoint failed, restarting...")
			time.Sleep(1 * time.Second)
		}
	}
}

// loadTLSConfig dynamically loads the TLS certificates and keys.
func loadTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	// Load the server certificate and private key.
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate and key: %w", err)
	}

	// Load the CA certificate.
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// Create a CA certificate pool.
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificate to pool")
	}

	// Return a new TLS configuration.
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{http2.NextProtoTLS},
	}, nil
}
