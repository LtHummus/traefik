package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// makePebbleProxyCert mints a throwaway CA and a leaf certificate for the "pebble" SNI, so the ARI
// proxy can serve TLS that Traefik trusts. lego forces the SNI to "pebble" (LEGO_CA_SERVER_NAME) and
// requires an HTTPS directory, so the leaf must be valid for that name. The CA PEM is returned so it
// can be added to Traefik's trust bundle.
func makePebbleProxyCert(t *testing.T) ([]byte, tls.Certificate) {
	t.Helper()

	now := time.Now()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "traefik-ari-test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "pebble"},
		DNSNames:     []string{"pebble"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	return caPEM, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

// startARIProxy stands up an HTTPS server that fronts pebble's ACME directory but rewrites the
// renewalInfo endpoint to point back at itself, so ARI lookups can be driven by the test while
// issuance still flows directly to pebble. suggestRenewNow decides, per certID, whether the served
// window is in the past (renew now) or far in the future (defer). The returned counter records how
// many renewalInfo lookups have been served, which lets a test assert ARI was actually consulted.
//
// Traefik trusts both pebble's minica (for issuance, which still goes to pebble) and the proxy's CA
// (for the directory and ARI). Both certificates are for the "pebble" SNI, matching the forced
// LEGO_CA_SERVER_NAME, so either connection validates. The returned string is the proxy base URL.
func startARIProxy(t *testing.T, pebbleIP string, suggestRenewNow func(certID string) bool) (string, *atomic.Int64) {
	t.Helper()

	caPath, err := filepath.Abs("fixtures/acme/ssl/pebble.minica.pem")
	require.NoError(t, err)
	minicaPEM, err := os.ReadFile(caPath)
	require.NoError(t, err)

	pebblePool := x509.NewCertPool()
	require.True(t, pebblePool.AppendCertsFromPEM(minicaPEM))

	// The proxy reaches pebble over TLS, trusting the minica with the forced "pebble" SNI.
	pebbleClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: "pebble", RootCAs: pebblePool},
	}}
	pebbleBase := fmt.Sprintf("https://%s", net.JoinHostPort(pebbleIP, "14000"))

	proxyCAPEM, leaf := makePebbleProxyCert(t)

	// Extend Traefik's trust bundle with the proxy CA (alongside the minica) for the duration of
	// the test, so it accepts both the proxy (directory + ARI) and pebble (issuance).
	bundle := append(append([]byte{}, minicaPEM...), proxyCAPEM...)
	bundlePath := filepath.Join(t.TempDir(), "ari-bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, bundle, 0o600))

	t.Setenv("LEGO_CA_CERTIFICATES", bundlePath)

	var renewalChecks atomic.Int64
	var proxyURL string

	mux := http.NewServeMux()

	mux.HandleFunc("/dir", func(w http.ResponseWriter, _ *http.Request) {
		resp, err := pebbleClient.Get(pebbleBase + "/dir")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		var dir map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		// For now, we trap the request for `/renewalInfo` so we can respond however we want. All other endpoints just
		// get passed through to pebble upstream. One future addition that might make sense is to actuall make this a
		// reverse proxy with more customization so we can validate the ARI renewal succeeded (i.e. we need to capture
		// the order and see that the replaces field is set properly)
		dir["renewalInfo"] = proxyURL + "/renewalInfo"

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(dir)
	})

	mux.HandleFunc("/renewalInfo/", func(w http.ResponseWriter, r *http.Request) {
		renewalChecks.Add(1)

		certID := strings.TrimPrefix(r.URL.Path, "/renewalInfo/")

		now := time.Now().UTC()
		start, end := now.Add(1000*time.Hour), now.Add(1001*time.Hour) // just return some time far in the future for non-renewal
		if suggestRenewNow(certID) {
			start, end = now.Add(-2*time.Hour), now.Add(-1*time.Hour) // it's time!
		}

		w.Header().Set("Retry-After", "10")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"suggestedWindow": map[string]string{
				"start": start.Format(time.RFC3339),
				"end":   end.Format(time.RFC3339),
			},
		})
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &http.Server{
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{leaf}},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() {
		_ = srv.Close()
	})

	proxyURL = "https://" + ln.Addr().String()

	return proxyURL, &renewalChecks
}
