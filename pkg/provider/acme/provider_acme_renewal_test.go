package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/types"
)

func Test_getCertificateRenewDurations(t *testing.T) {
	testCases := []struct {
		desc                  string
		certificatesDurations int
		expectRenewPeriod     time.Duration
		expectRenewInterval   time.Duration
	}{
		{
			desc:                  "Less than 24 Hours certificates: 20 minutes renew period, 1 minutes renew interval",
			certificatesDurations: 1,
			expectRenewPeriod:     time.Minute * 20,
			expectRenewInterval:   time.Minute,
		},
		{
			desc:                  "1 Year certificates: 4 months renew period, 1 week renew interval",
			certificatesDurations: 24 * 365,
			expectRenewPeriod:     time.Hour * 24 * 30 * 4,
			expectRenewInterval:   time.Hour * 24 * 7,
		},
		{
			desc:                  "265 Days certificates: 30 days renew period, 1 day renew interval",
			certificatesDurations: 24 * 265,
			expectRenewPeriod:     time.Hour * 24 * 30,
			expectRenewInterval:   time.Hour * 24,
		},
		{
			desc:                  "90 Days certificates: 30 days renew period, 1 day renew interval",
			certificatesDurations: 24 * 90,
			expectRenewPeriod:     time.Hour * 24 * 30,
			expectRenewInterval:   time.Hour * 24,
		},
		{
			desc:                  "45 Days certificates (Let's Encrypt 2028 standard): 10 days renew period, 12 hour renew interval",
			certificatesDurations: 24 * 45,
			expectRenewPeriod:     time.Hour * 24 * 10,
			expectRenewInterval:   time.Hour * 12,
		},
		{
			desc:                  "30 Days certificates: 10 days renew period, 12 hour renew interval",
			certificatesDurations: 24 * 30,
			expectRenewPeriod:     time.Hour * 24 * 10,
			expectRenewInterval:   time.Hour * 12,
		},
		{
			desc:                  "7 Days certificates: 2 days renew period, 2 hour renew interval",
			certificatesDurations: 24 * 7,
			expectRenewPeriod:     time.Hour * 24 * 2,
			expectRenewInterval:   time.Hour * 2,
		},
		{
			desc:                  "160 hour certificate (Let's Encrypt 'shortlived' profile): 2 days renew period, 2 hour renew interval",
			certificatesDurations: 160,
			expectRenewPeriod:     time.Hour * 24 * 2,
			expectRenewInterval:   time.Hour * 2,
		},
		{
			desc:                  "24 Hours certificates: 6 hours renew period, 10 minutes renew interval",
			certificatesDurations: 24,
			expectRenewPeriod:     time.Hour * 6,
			expectRenewInterval:   time.Minute * 10,
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			renewPeriod, renewInterval := getCertificateRenewDurations(test.certificatesDurations)
			assert.Equal(t, test.expectRenewPeriod, renewPeriod)
			assert.Equal(t, test.expectRenewInterval, renewInterval)
		})
	}
}

func makeTestCertPEM(t *testing.T, notBefore time.Time, notAfter time.Time) ([]byte, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "traefik.wtf"},
		DNSNames:     []string{"traefik.wtf"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

func Test_getNextCheckTime(t *testing.T) {
	testCases := []struct {
		desc     string
		waits    []time.Duration
		fallback time.Duration
		expected time.Duration
	}{
		{
			desc:     "no certs means fallback",
			waits:    nil,
			fallback: 12 * time.Hour,
			expected: 12 * time.Hour,
		},
		{
			desc:     "zero wait times means fallback",
			waits:    []time.Duration{0, 0},
			fallback: 12 * time.Hour,
			expected: 12 * time.Hour,
		},
		{
			desc:     "shortest wait is picked",
			waits:    []time.Duration{48 * time.Hour, 30 * time.Minute, 24 * time.Hour},
			fallback: 2 * time.Hour,
			expected: 30 * time.Minute,
		},
		{
			desc:     "long waits are not overriden by a short fallback",
			waits:    []time.Duration{24 * time.Hour, 96 * time.Hour},
			fallback: 1 * time.Hour,
			expected: 24 * time.Hour,
		},
		{
			desc:     "zero, negative waits are ignored",
			waits:    []time.Duration{1 * time.Hour, -1 * time.Hour, 0},
			fallback: 2 * time.Hour,
			expected: 1 * time.Hour,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			certs := make([]certRenewalInfo, len(test.waits))
			for i, curr := range test.waits {
				certs[i] = certRenewalInfo{timeToWaitForNextCheck: curr}
			}

			assert.Equal(t, test.expected, getNextCheckTime(certs, test.fallback))
		})
	}
}

func Test_shouldRenewBasedOnTime(t *testing.T) {
	now := time.Now().UTC()

	testCases := []struct {
		desc     string
		cert     *x509.Certificate
		period   time.Duration
		expected bool
	}{
		{
			desc:     "nil always renews",
			cert:     nil,
			period:   30 * 24 * time.Hour,
			expected: true,
		},
		{
			desc:     "expiration inside period renews",
			cert:     &x509.Certificate{NotAfter: now.Add(2 * 24 * time.Hour)},
			period:   30 * 24 * time.Hour,
			expected: true,
		},
		{
			desc:     "expiration outside period does not renew",
			cert:     &x509.Certificate{NotAfter: now.Add(60 * 24 * time.Hour)},
			period:   30 * 24 * time.Hour,
			expected: false,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, test.expected, shouldRenewBasedOnTime(test.cert, test.period))
		})
	}
}

func Test_certLifetimeHours(t *testing.T) {
	now := time.Now().UTC()
	crt := &x509.Certificate{
		NotBefore: now,
		NotAfter:  now.Add(90 * 24 * time.Hour),
	}

	assert.Equal(t, 90*24, certLifetimeHours(crt))
}

func Test_getRenewalInformation_unparsableCertStillWorks(t *testing.T) {
	p := &Provider{
		Configuration: &Configuration{
			DisableARI:           false,
			CertificatesDuration: 24 * 90,
		},
	}

	cs := &CertAndStore{
		Certificate: Certificate{
			Domain:      types.Domain{Main: "traefik.wtf"},
			Certificate: []byte("this is not a valid certificate"),
			Key:         []byte("this is not a valid key -- or it shouldn't be a valid key"),
		},
	}

	assert.NotPanics(t, func() {
		info := p.getRenewalInformation(t.Context(), cs, time.Hour)

		assert.True(t, info.shouldRenew)
		assert.Nil(t, info.x509Cert)
		assert.False(t, info.IsARI())
		assert.Positive(t, info.timeToWaitForNextCheck)
	})
}

func Test_getRenewalInformation_timeBased(t *testing.T) {
	// this test only tests the timebased stuff. The ARI based stuff will appear in integration tests since it needs
	// an actual server to test against

	p := &Provider{Configuration: &Configuration{
		DisableARI: true,
	}}

	now := time.Now().UTC()

	testCases := []struct {
		desc        string
		notBefore   time.Time
		notAfter    time.Time
		expectRenew bool
	}{
		{
			desc:        "fresh 90-day cert is not due",
			notBefore:   now,
			notAfter:    now.Add(90 * 24 * time.Hour),
			expectRenew: false,
		},
		{
			desc:        "90-day cert near expiration that's due",
			notBefore:   now.Add(-85 * 24 * time.Hour),
			notAfter:    now.Add(5 * 24 * time.Hour),
			expectRenew: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			certPEM, keyPEM := makeTestCertPEM(t, test.notBefore, test.notAfter)
			cs := &CertAndStore{
				Certificate: Certificate{
					Domain:      types.Domain{Main: "traefik.wtf"},
					Certificate: certPEM,
					Key:         keyPEM,
				},
			}

			info := p.getRenewalInformation(t.Context(), cs, time.Hour)
			assert.Equal(t, test.expectRenew, info.shouldRenew)
			assert.False(t, info.IsARI())
			require.NotNil(t, info.x509Cert)
		})
	}
}
