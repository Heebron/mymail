// Command mymail-dkim generates RSA public and private keys and a DNS TXT record for DKIM setup.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"mymail/dkim"
)

// Result represents the generated DKIM key pair and DNS record metadata.
type Result struct {
	Domain        string `json:"domain"`
	Selector      string `json:"selector"`
	Bits          int    `json:"bits"`
	RecordName    string `json:"record_name"`
	RecordType    string `json:"record_type"`
	RecordValue   string `json:"record_value"`
	ZoneEntry     string `json:"zone_entry"`
	PrivateKeyPEM string `json:"private_key_pem"`
	PublicKeyPEM  string `json:"public_key_pem"`
	PublicKeyDNS  string `json:"public_key_dns"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mymail-dkim", flag.ContinueOnError)
	fs.SetOutput(stderr)

	domainFlag := fs.String("domain", "", "target domain name (e.g. example.com)")
	fs.StringVar(domainFlag, "d", "", "alias for -domain")

	selectorFlag := fs.String("selector", "default", "DKIM selector name")
	fs.StringVar(selectorFlag, "s", "default", "alias for -selector")

	bitsFlag := fs.Int("bits", 2048, "RSA key size in bits (minimum 1024, recommended 2048)")
	fs.IntVar(bitsFlag, "b", 2048, "alias for -bits")

	outDirFlag := fs.String("out", "", "directory to write generated key and DNS record files")
	fs.StringVar(outDirFlag, "dir", "", "alias for -out")

	privOutFlag := fs.String("priv-out", "", "custom file path to write private key PEM")
	pubOutFlag := fs.String("pub-out", "", "custom file path to write public key PEM")
	dnsOutFlag := fs.String("dns-out", "", "custom file path to write DNS TXT record")

	jsonFlag := fs.Bool("json", false, "output result formatted as JSON")
	quietFlag := fs.Bool("quiet", false, "suppress decorative headers and output DNS TXT record value only")
	fs.BoolVar(quietFlag, "q", false, "alias for -quiet")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	domain := strings.TrimSpace(*domainFlag)
	if domain == "" && fs.NArg() > 0 {
		domain = strings.TrimSpace(fs.Arg(0))
	}
	if domain == "" {
		domain = "example.com"
	}
	domain = strings.TrimSuffix(domain, ".")

	selector := strings.TrimSpace(*selectorFlag)
	if selector == "" {
		selector = "default"
	}

	privKey, err := dkim.GenerateKeyPair(*bitsFlag)
	if err != nil {
		fmt.Fprintf(stderr, "generate key pair: %v\n", err)
		return 1
	}

	privPEM := dkim.PEMEncodePrivateKey(privKey)
	pubPEM, err := dkim.PEMEncodePublicKey(&privKey.PublicKey)
	if err != nil {
		fmt.Fprintf(stderr, "encode public key: %v\n", err)
		return 1
	}

	pubDNS, err := dkim.PublicKeyToDNSData(&privKey.PublicKey)
	if err != nil {
		fmt.Fprintf(stderr, "encode public key for DNS: %v\n", err)
		return 1
	}

	recName, recVal, err := dkim.FormatDNSTXTRecord(selector, domain, &privKey.PublicKey)
	if err != nil {
		fmt.Fprintf(stderr, "format DNS record: %v\n", err)
		return 1
	}

	zoneEntry, err := dkim.FormatDNSZoneEntry(selector, domain, &privKey.PublicKey)
	if err != nil {
		fmt.Fprintf(stderr, "format DNS zone entry: %v\n", err)
		return 1
	}

	privPath := strings.TrimSpace(*privOutFlag)
	pubPath := strings.TrimSpace(*pubOutFlag)
	dnsPath := strings.TrimSpace(*dnsOutFlag)

	if *outDirFlag != "" {
		if err := os.MkdirAll(*outDirFlag, 0755); err != nil {
			fmt.Fprintf(stderr, "create output directory: %v\n", err)
			return 1
		}
		if privPath == "" {
			privPath = filepath.Join(*outDirFlag, fmt.Sprintf("%s.private.key", selector))
		}
		if pubPath == "" {
			pubPath = filepath.Join(*outDirFlag, fmt.Sprintf("%s.public.key", selector))
		}
		if dnsPath == "" {
			dnsPath = filepath.Join(*outDirFlag, fmt.Sprintf("%s.dns.txt", selector))
		}
	}

	if privPath != "" {
		if dir := filepath.Dir(privPath); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				fmt.Fprintf(stderr, "create private key directory: %v\n", err)
				return 1
			}
		}
		if err := os.WriteFile(privPath, []byte(privPEM), 0600); err != nil {
			fmt.Fprintf(stderr, "write private key file: %v\n", err)
			return 1
		}
	}

	if pubPath != "" {
		if dir := filepath.Dir(pubPath); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				fmt.Fprintf(stderr, "create public key directory: %v\n", err)
				return 1
			}
		}
		if err := os.WriteFile(pubPath, []byte(pubPEM), 0644); err != nil {
			fmt.Fprintf(stderr, "write public key file: %v\n", err)
			return 1
		}
	}

	if dnsPath != "" {
		if dir := filepath.Dir(dnsPath); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				fmt.Fprintf(stderr, "create DNS record directory: %v\n", err)
				return 1
			}
		}
		dnsContent := fmt.Sprintf("; DKIM TXT record for %s\n; Selector: %s\n%s\n", domain, selector, zoneEntry)
		if err := os.WriteFile(dnsPath, []byte(dnsContent), 0644); err != nil {
			fmt.Fprintf(stderr, "write DNS record file: %v\n", err)
			return 1
		}
	}

	if *jsonFlag {
		res := Result{
			Domain:        domain,
			Selector:      selector,
			Bits:          *bitsFlag,
			RecordName:    recName,
			RecordType:    "TXT",
			RecordValue:   recVal,
			ZoneEntry:     zoneEntry,
			PrivateKeyPEM: privPEM,
			PublicKeyPEM:  pubPEM,
			PublicKeyDNS:  pubDNS,
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(stderr, "encode JSON: %v\n", err)
			return 1
		}
		return 0
	}

	if *quietFlag {
		fmt.Fprintln(stdout, recVal)
		return 0
	}

	fmt.Fprintln(stdout, "================================================================================")
	fmt.Fprintln(stdout, "DKIM Key Pair & DNS TXT Record Generator")
	fmt.Fprintln(stdout, "================================================================================")
	fmt.Fprintf(stdout, "Domain:       %s\n", domain)
	fmt.Fprintf(stdout, "Selector:     %s\n", selector)
	fmt.Fprintf(stdout, "Key Size:     %d-bit RSA\n", *bitsFlag)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "--------------------------------------------------------------------------------")
	fmt.Fprintln(stdout, "DNS TXT Record")
	fmt.Fprintln(stdout, "--------------------------------------------------------------------------------")
	fmt.Fprintf(stdout, "Record Name:  %s\n", recName)
	fmt.Fprintf(stdout, "Record Type:  TXT\n")
	fmt.Fprintf(stdout, "Record Value: %q\n", recVal)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Zone File Entry:")
	fmt.Fprintf(stdout, "%s\n", zoneEntry)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "--------------------------------------------------------------------------------")
	fmt.Fprintln(stdout, "Private Key (Keep secure! Used by MyMail to sign outgoing messages)")
	fmt.Fprintln(stdout, "--------------------------------------------------------------------------------")
	fmt.Fprint(stdout, privPEM)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "--------------------------------------------------------------------------------")
	fmt.Fprintln(stdout, "Public Key (PEM format)")
	fmt.Fprintln(stdout, "--------------------------------------------------------------------------------")
	fmt.Fprint(stdout, pubPEM)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "--------------------------------------------------------------------------------")
	fmt.Fprintln(stdout, "MyMail Configuration Snippet (config.yaml)")
	fmt.Fprintln(stdout, "--------------------------------------------------------------------------------")
	if privPath != "" && pubPath != "" {
		fmt.Fprintf(stdout, "dkim:\n  domain: %s\n  selector: %s\n  private_key: %s\n  public_key: %s\n", domain, selector, privPath, pubPath)
	} else {
		fmt.Fprintf(stdout, "dkim:\n  domain: %s\n  selector: %s\n  private_key: /etc/mymail/%s.private.key\n  public_key: /etc/mymail/%s.public.key\n", domain, selector, selector, selector)
	}
	if privPath != "" || pubPath != "" || dnsPath != "" {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "--------------------------------------------------------------------------------")
		fmt.Fprintln(stdout, "Files Written")
		fmt.Fprintln(stdout, "--------------------------------------------------------------------------------")
		if privPath != "" {
			fmt.Fprintf(stdout, "Private Key: %s (mode 0600)\n", privPath)
		}
		if pubPath != "" {
			fmt.Fprintf(stdout, "Public Key:  %s (mode 0644)\n", pubPath)
		}
		if dnsPath != "" {
			fmt.Fprintf(stdout, "DNS Record:  %s (mode 0644)\n", dnsPath)
		}
	}
	fmt.Fprintln(stdout, "================================================================================")
	return 0
}
