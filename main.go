package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/andersmic/cert-manager-webhook-dnsservices/dnssvc"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&dnsServicesDNSProviderSolver{},
	)
}

// dnsServicesDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type dnsServicesDNSProviderSolver struct {
	client *kubernetes.Clientset
}

type dnsServicesDNSProviderConfig struct {
	UsernameSecretKeyRef cmmeta.SecretKeySelector `json:"usernameSecretKeyRef"`
	PasswordSecretKeyRef cmmeta.SecretKeySelector `json:"passwordSecretKeyRef"`
}

// Type holding credential.
type credential struct {
	Username string
	Password string
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *dnsServicesDNSProviderSolver) Name() string {
	return "dnsServices"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *dnsServicesDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("Present: namespace=%s, zone=%s, fqdn=%s", ch.ResourceNamespace, ch.ResolvedZone, ch.ResolvedFQDN)

	// Load config.
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("unable to load config: %v", err)
	}
	klog.Infof("Decoded configuration %v", cfg)

	// Get credentials for connecting to Loopia.
	creds, err := c.getCredentials(&cfg, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("unable to get credential: %v", err)
	}
	klog.Infof("Decoded credentials: %v", creds)

	addErr := addDNSRecord(creds, ch)
	if addErr != nil {
		return addErr
	}
	klog.Infof("Presented txt record %v", ch.ResolvedFQDN)

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *dnsServicesDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("CleanUp: namespace=%s, zone=%s, fqdn=%s", ch.ResourceNamespace, ch.ResolvedZone, ch.ResolvedFQDN)

	// Load config.
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	// Get credentials for connecting to dns.Services
	creds, err := c.getCredentials(&cfg, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("unable to get credential: %v", err)
	}
	klog.Infof("Decoded credentials: %v", creds)

	klog.Infof("Cleanup dnsServices Domain %s.%s", ch.ResolvedZone, ch.ResolvedFQDN)
	rmErr := removeDNSRecord(creds, ch)
	if rmErr != nil {
		klog.Errorf("Error removing dns record: %s", rmErr)
		return rmErr
	}
	klog.Infof("Cleanup record %v", ch.ResolvedFQDN)
	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *dnsServicesDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	///// UNCOMMENT THE BELOW CODE TO MAKE A KUBERNETES CLIENTSET AVAILABLE TO
	///// YOUR CUSTOM DNS PROVIDER
	klog.Infof("Call function Initialize")

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (dnsServicesDNSProviderConfig, error) {
	cfg := dnsServicesDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

// Get Loopia API credentials from Kubernetes secret.
func (c *dnsServicesDNSProviderSolver) getCredentials(cfg *dnsServicesDNSProviderConfig, namespace string) (*credential, error) {
	creds := credential{}

	// Get Username.
	klog.V(2).Infof("Trying to load secret `%s` with key `%s`", cfg.UsernameSecretKeyRef.Name, cfg.UsernameSecretKeyRef.Key)
	usernameSecret, err := c.client.CoreV1().Secrets(namespace).Get(context.Background(), cfg.UsernameSecretKeyRef.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to load secret %q: %s", namespace+"/"+cfg.UsernameSecretKeyRef.Name, err.Error())
	}
	if username, ok := usernameSecret.Data[cfg.UsernameSecretKeyRef.Key]; ok {
		creds.Username = string(username)
	} else {
		return nil, fmt.Errorf("no key %q in secret %q", cfg.UsernameSecretKeyRef, namespace+"/"+cfg.UsernameSecretKeyRef.Name)
	}

	// Get Password.
	klog.V(2).Infof("Trying to load secret `%s` with key `%s`", cfg.PasswordSecretKeyRef.Name, cfg.PasswordSecretKeyRef.Key)
	passwordSecret, err := c.client.CoreV1().Secrets(namespace).Get(context.Background(), cfg.PasswordSecretKeyRef.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to load secret %q: %s", namespace+"/"+cfg.PasswordSecretKeyRef.Name, err.Error())
	}
	if password, ok := passwordSecret.Data[cfg.PasswordSecretKeyRef.Key]; ok {
		creds.Password = string(password)
	} else {
		return nil, fmt.Errorf("no key %q in secret %q", cfg.PasswordSecretKeyRef, namespace+"/"+cfg.PasswordSecretKeyRef.Name)
	}

	return &creds, nil
}

func findZone(dnsClient *dnssvc.DnsSvcClient, name string) (*dnssvc.ZoneRec, error) {
	services, err := dnsClient.LoadDNS()
	if err != nil {
		return nil, err
	}
	return services.GetZoneByName(name), nil
}

func addDNSRecord(cred *credential, ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("Add DNS TXT entry %s := %s", ch.ResolvedFQDN, ch.Key)
	dnsClient := dnssvc.DnsSvcClient{}
	loginErr := dnsClient.Login(cred.Username, cred.Password)
	if loginErr != nil {
		return loginErr
	}

	entry, domain := getDomainAndEntry(ch)
	klog.Infof("Add DNS TXT entry %s - %s := %s", domain, entry, ch.Key)

	zone, err := findZone(&dnsClient, domain)
	if err != nil {
		return err
	}

	txt := dnssvc.DNSRecord{
		Name:    entry,
		Ttl:     "3600",
		Type:    "TXT",
		Content: ch.Key,
	}

	klog.Infof("Adding record %v", txt)
	addErr := dnsClient.AddRecord(zone, &txt)
	if addErr != nil {
		return addErr
	}

	klog.Infof("Record added")

	return nil
}

func removeDNSRecord(cred *credential, ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("Removing DNS TXT entry %s", ch.ResolvedFQDN)

	dnsClient := dnssvc.DnsSvcClient{}
	loginErr := dnsClient.Login(cred.Username, cred.Password)
	if loginErr != nil {
		return loginErr
	}

	entry, domain := getDomainAndEntry(ch)
	klog.Infof("Remove DNS TXT entry %s from domain %s", entry, domain)

	zone, err := findZone(&dnsClient, domain)
	if err != nil {
		return err
	}

	details, err := dnsClient.GetDetails(zone)
	if err != nil {
		return err
	}

	t := "TXT"

	r := details.FindRecordByName(t, ch.ResolvedFQDN)
	if r == nil {
		r = details.FindRecordByName(t, entry)
		if r == nil {
			klog.Infof("Record not found: %s / %s. IGNORE!", entry, ch.ResolvedFQDN)
			return nil
		}
	}
	klog.Infof("Found record: %v", r)

	rmErr := dnsClient.RemoveRecord(zone, r)
	if rmErr != nil {
		return rmErr
	}
	klog.Infof("Record removed")

	return nil
}

func getDomainAndEntry(ch *v1alpha1.ChallengeRequest) (string, string) {
	// Strip the zone from the fqdn to yield the entry (subdomain)
	entry := strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone)
	entry = strings.TrimSuffix(entry, ".") // Also remove any stray .

	// Remove trailing . from domain
	domain := strings.TrimSuffix(ch.ResolvedZone, ".")

	return entry, domain
}
