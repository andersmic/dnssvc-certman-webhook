package main

import (
	"os"
	"time"
	"strconv"
	"testing"

	"github.com/jetstack/cert-manager/test/acme/dns"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
	strictmodeenv = os.Getenv("TEST_STRICT_MODE")
)

func TestRunsSuite(t *testing.T) {
	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.
	//
	var strictmode, err = strconv.ParseBool(strictmodeenv)
	if err != nil {
		strictmode = false
	}
	// Uncomment the below fixture when implementing your custom DNS provider
	solver := &dnsServicesDNSProviderSolver{}
	fixture := dns.NewFixture(solver,
		dns.SetStrict(strictmode),
		dns.SetResolvedZone(zone),
		dns.SetAllowAmbientCredentials(false),
		dns.SetManifestPath("testdata/my-custom-solver"),
		dns.SetPollInterval(time.Second*60),
		dns.SetPropagationLimit(time.Minute*30),		
	)
	//need to uncomment and  RunConformance delete runBasic and runExtended once https://github.com/cert-manager/cert-manager/pull/4835 is merged
	fixture.RunConformance(t)

}
