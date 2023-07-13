package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/fastnetmon/fastnetmon-go"
)

type Configuration struct {
	Log_path string `json:"log_path"`

	// f5, f5_xc or path or cloudflare
	ProviderName string `json:"provider_name"`

	// F5 Silverline credentials
	F5Email    string `json:"f5_email"`
	F5Password string `json:"f5_password"`

	// F5 XC credentials
	F5PemCertificatePath    string `json:"f5_pem_certificate_path"`
	F5PemCertificateKeyPath string `json:"f5_pem_certificate_key_path"`

	// Their original format
	F5P12CertificatePath     string `json:"f5_p12_certificate_path"`
	F5P12CertificatePassword string `json:"f5_p12_certificate_password"`

	// Path credentials
	PathUsername string `json:"path_username"`
	PathPassword string `json:"path_password"`

	// Cloudflare credentials
	CloudflareAPIToken string `json:"cloudflare_api_token"`

	CloudflareAccountID string `json:"cloudflare_account_id"`

	CloudflareNextHop string `json:"cloudflare_next_hop"`

	// zero by default
	CloudflarePriority int `json:"cloudflare_priority"`

	// Zero by default
	CloudflareWeight int `json:"cloudflare_weight"`
}

var fast_logger = log.New(os.Stderr, fmt.Sprintf(" %d ", os.Getpid()), log.LstdFlags)

var f5_api_url string = "https://portal.f5silverline.com/api/v1/"

var f5_xc_api_url string = "https://f5-neteng.console.ves.volterra.io"

var path_api_url string = "https://api.path.net/"

// Emulate successful auth and try to issue announce commands
var fake_auth = false

func main() {
	conf := Configuration{Log_path: "/var/log/fastnetmon/fastnetmon_scrubbing_services_integration.log"}

	configuration_file_path := "/etc/fastnetmon_scrubbing_services_integration.json"

	conf_file_data, err := ioutil.ReadFile(configuration_file_path)

	if err != nil {
		fast_logger.Fatalf("Cannot open configuration file: %v", configuration_file_path)
	}

	err = json.Unmarshal([]byte(conf_file_data), &conf)

	if err != nil {
		fast_logger.Fatalf("Cannot decode configuration file %s: %v", configuration_file_path, err)
	}

	if conf.Log_path == "" {
		fast_logger.Fatal("Please set non empty value for log_path")
	}

	log_file, err := os.OpenFile(conf.Log_path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)

	if err != nil {
		fast_logger.Fatalf("Cannot open log file: %v", err)
	}

	defer log_file.Close()

	multi_writer := io.MultiWriter(os.Stdout, log_file)

	fast_logger.SetOutput(multi_writer)

	fast_logger.Printf("Prepared to read data from stdin")
	stdin_data, err := ioutil.ReadAll(os.Stdin)

	if err != nil {
		fast_logger.Fatal("Cannot read data from stdin")
	}

	callback_data := fastnetmon.CallbackDetails{}

	fast_logger.Printf("Callback raw data: %s", stdin_data)

	err = json.Unmarshal([]byte(stdin_data), &callback_data)

	if err != nil {
		fast_logger.Printf("Raw data: %s", stdin_data)
		fast_logger.Fatalf("Cannot unmarshal data: %v", err)
	}

	// Scope can be per host or total hostgroups
	alert_scope := callback_data.AlertScope

	if alert_scope == "" || alert_scope == "host" {
		// All fine
	} else if alert_scope == "hostgroup" {
		fast_logger.Fatalf("We do not support total hostgroups in current version, please talk with support@fastnetmon.com")
	} else {
		fast_logger.Fatalf("Unknown scope: %s", alert_scope)
	}

	action := callback_data.Action

	fast_logger.Printf("Action: %s", action)

	fast_logger.Printf("Callback decoded data: %+v", callback_data)

	if action != "ban" && action != "unban" {
		fast_logger.Fatalf("Unknown action type: %s", action)
	}

	// By default we do announce
	withdrawal := false

	if action == "unban" {
		withdrawal = true
	}

	fast_logger.Printf("Attack is against IP %s", callback_data.IP)

	parsed_ip := net.ParseIP(callback_data.IP)

	if parsed_ip == nil {
		fast_logger.Fatalf("Cannot decode IP: %v", callback_data.IP)
	}

	// Convert to 4 byte representation
	ip_v4_address := parsed_ip.To4()

	if ip_v4_address == nil {
		fast_logger.Fatalf("IPv6 addresses are not supported")
	}

	// Set last byte to zero to create network address
	ip_v4_address[3] = 0

	// By default, we use use /24 for prefix
	prefix_to_announce := net.IPNet{IP: ip_v4_address, Mask: net.CIDRMask(24, 32)}

	network_cidr_prefix := prefix_to_announce.String()

	fast_logger.Printf("Prefix to announce: %v", network_cidr_prefix)

	if conf.ProviderName == "f5" {

		if conf.F5Email == "" {
			fast_logger.Fatal("Please set f5_email field in configuration")
		}

		if conf.F5Password == "" {
			fast_logger.Fatal("Please set f5_password field in configuration")
		}

		auth_token, err := f5_auth(conf.F5Email, conf.F5Password, fake_auth)

		if err != nil {
			fast_logger.Fatalf("Auth failed: %v", err)
		}

		fast_logger.Printf("Successful auth with token: %v", auth_token)

		if withdrawal {
			fast_logger.Printf("Preparing to withdraw prefix: %v", network_cidr_prefix)
		} else {
			fast_logger.Printf("Preparing to announce prefix: %v", network_cidr_prefix)
		}

		err = f5_announce_route(auth_token, network_cidr_prefix, withdrawal)

		if err != nil {
			fast_logger.Fatalf("Cannot announce prefix: %v with error: %v", network_cidr_prefix, err)
		}

	} else if conf.ProviderName == "f5_xc" {
		if conf.F5P12CertificatePath == "" {

			if conf.F5PemCertificatePath == "" {
				fast_logger.Fatal("Please set f5_certificate_path field in configuration")
			}

			if conf.F5PemCertificateKeyPath == "" {
				fast_logger.Fatal("Please set f5_certificate_key_path field in configuration")
			}

			// All fine
		} else {
			// P12 certificate specified
		}

		err = f5_xc_announce_route(conf.F5PemCertificatePath, conf.F5PemCertificateKeyPath, conf.F5P12CertificatePath, conf.F5P12CertificatePassword, network_cidr_prefix, withdrawal)

		if err != nil {
			fast_logger.Fatalf("Cannot announce prefix: %v with error: %v", network_cidr_prefix, err)
		}

	} else if conf.ProviderName == "path" {
		if conf.PathUsername == "" {
			fast_logger.Fatal("Please set path_username field in configuration")
		}

		if conf.PathPassword == "" {
			fast_logger.Fatal("Please set path_password field in configuration")
		}

		auth_token, err := path_auth(conf.PathUsername, conf.PathPassword, fake_auth)

		if err != nil {
			fast_logger.Fatalf("Cannot auth: %v", err)
		}

		fast_logger.Printf("Successful auth with token: %s", auth_token)

		if withdrawal {
			fast_logger.Printf("Preparing to withdraw prefix: %v", network_cidr_prefix)
		} else {
			fast_logger.Printf("Preparing to announce prefix: %v", network_cidr_prefix)
		}

		err = path_announce_route(auth_token, network_cidr_prefix, withdrawal)

		if err != nil {
			fast_logger.Fatalf("Cannot announce prefix: %v with error: %v", network_cidr_prefix, err)
		}
	} else if conf.ProviderName == "cloudflare" {
		if conf.CloudflareAPIToken == "" {
			fast_logger.Fatal("Please set cloudflare_api_token field in configuration")
		}

		if conf.CloudflareAccountID == "" {
			fast_logger.Fatal("Please set cloudflare_account_id field in configuration")
		}

		if conf.CloudflareNextHop == "" {
			fast_logger.Fatal("Please set cloudflare_next_hop field in configuration")
		}

		// We support only scoped API token which does not need email
		cloudflare_api, err := cloudflare.NewWithAPIToken(conf.CloudflareAPIToken)

		if err != nil {
			fast_logger.Fatalf("Cannot create Cloudflare API client: %v", err)
		}

		ctx := context.Background()

		// Verify token for correctness
		// It's not 100% required but I think it's good point to have it
		user_information, err := cloudflare_api.VerifyAPIToken(ctx)

		if err != nil {
			fast_logger.Fatalf("Cannot check API token: %v", err)
		}

		fast_logger.Printf("Successfully verified token: %+v", user_information)

		fast_logger.Printf("Getting list of static Magic Transit Routes")

		magic_transit_tunnels, err := cloudflare_api.ListMagicTransitStaticRoutes(ctx, conf.CloudflareAccountID)

		if err != nil {
			fast_logger.Fatalf("Cannot get Magic Transit tunnels: %v", err)
		}

		fast_logger.Printf("Successfully got %d tunnels from Cloudflare", len(magic_transit_tunnels))

		// Lookup static route id as it may exist
		static_route_id := find_magic_transit_route_by_prefix(magic_transit_tunnels, network_cidr_prefix)

		if withdrawal {
			// Announce withdrawal
			if static_route_id == "" {
				fast_logger.Fatalf("I cannot find any active announces for prefix: %s", network_cidr_prefix)
			}

			fast_logger.Printf("Preparing to withdraw static announce with id %s", static_route_id)

			_, err := cloudflare_api.DeleteMagicTransitStaticRoute(ctx, conf.CloudflareAccountID, static_route_id)

			if err != nil {
				fast_logger.Fatalf("Failed to remove static announce: %s", err)
			}

			fast_logger.Printf("Successfully removed static announce")
		} else {
			// Announce
			if static_route_id != "" {
				fast_logger.Printf("Prefix is already active with ID: %s Skip announce", static_route_id)
				os.Exit(0)
			}

			static_route := cloudflare.MagicTransitStaticRoute{
				Prefix:      network_cidr_prefix,
				Description: "FastNetMon Advanced announce for prefix " + network_cidr_prefix,
				Nexthop:     conf.CloudflareNextHop,
			}

			if conf.CloudflarePriority != 0 {
				static_route.Priority = conf.CloudflarePriority
			}

			if conf.CloudflareWeight != 0 {
				static_route.Weight = conf.CloudflareWeight
			}

			fast_logger.Printf("Prepared announce: %+v", static_route)

			// Do announce
			_, err := cloudflare_api.CreateMagicTransitStaticRoute(ctx, conf.CloudflareAccountID, static_route)

			if err != nil {
				fast_logger.Fatalf("Cannot create route: %v", err)
			}

			fast_logger.Printf("Successfully created route")
		}

	} else {
		fast_logger.Fatalf("Unknown provider name, we support only 'f5' or 'path': %s", conf.ProviderName)
	}
}

// Returns id of prefix when found or empty string otherwise
func find_magic_transit_route_by_prefix(static_routes []cloudflare.MagicTransitStaticRoute, prefix string) string {
	if len(static_routes) == 0 {
		return ""
	}

	for _, route := range static_routes {
		if route.Prefix == prefix {
			return route.ID
		}
	}

	return ""
}

// Announce route for F5 XC
// On RHEL9 or Ubuntu 22.04 with legacy certificates enabled in /etc/ssl/openssl.cnf
/*
   [provider_sect]
   default = default_sect

   # Uncommented
   legacy = legacy_sect
   # Uncommented
   [default_sect]
   activate = 1

   # Uncommented
   [legacy_sect]
   activate = 1
*/
// As alternative to using their P12 certificates we can convert P12 to PEM as they're easier to operate from Go
// openssl pkcs12 -in f5-neteng.console.ves.volterra.io-service.p12 -clcerts -nokeys -out usercert.pem
// openssl pkcs12 -in f5-neteng.console.ves.volterra.io-service.p12 -nocerts -out userkey.pem -nodes
func f5_xc_announce_route(certificate_path string, certificate_key_path string, p12_certificate_path string, p12_certificate_password string, prefix string, withdrawal bool) error {
	var err error

	tls_client_config := &tls.Config{}

	if p12_certificate_path != "" {

		p12_data, err := ioutil.ReadFile(p12_certificate_path)

		if err != nil {
			return fmt.Errorf("Cannot read P12 certificate %s: %v", p12_certificate_path, err)
		}

		// Be careful with order of return values
		// We tried using Decode method from golang.org/x/crypto/pkcs12 but it returns: pkcs12: expected exactly two safe bags in the PFX PDU
		// https://github.com/RobotsAndPencils/buford/issues/8
		// https://github.com/golang/go/issues/14015
		// That's why we switched to github.com/SSLMate/go-pkcs12
		key, cert, _, err := pkcs12.DecodeChain(p12_data, p12_certificate_password)

		if err != nil {
			return fmt.Errorf("Cannot open P12 using provided password: %v", err)
		}

		log.Printf("Successfully extracted P12 certificates")

		tls_cert := tls.Certificate{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  key.(crypto.PrivateKey),
			Leaf:        cert,
		}

		tls_client_config.Certificates = []tls.Certificate{tls_cert}
	} else {

		// Load authentication certificates
		cert, err := tls.LoadX509KeyPair(certificate_path, certificate_key_path)

		if err != nil {
			return fmt.Errorf("Cannot load certificates: %v", err)
		}

		tls_client_config.Certificates = []tls.Certificate{cert}
	}

	tr := &http.Transport{
		TLSClientConfig: tls_client_config,
	}

	// Set reasonable timeout
	http_client := &http.Client{
		Transport: tr,
		Timeout:   time.Second * 60,
	}

	method := http.MethodPost
	url_path := "/api/infraprotect/namespaces/system/infraprotect_internet_prefix_advertisements"

	// Convert 10.0.0.0/24 to 10_0_0_0_24 to make proper name without special symbols
	// F5 API does not allow underscores:
	// label requirements: a DNS-1035 label must consist of lower case alphanumeric characters or '-',
	// start with an alphabetic character, and end with an alphanumeric character
	// Name should be less than 64 characters with a pattern of [a-z]([-a-z0-9]*[a-z0-9])? [DNS1035 Label]"}
	prefix_for_name := strings.ReplaceAll(prefix, ".", "-")
	prefix_for_name = strings.ReplaceAll(prefix_for_name, "/", "-")

	anouncement_name := "fastnetmon-" + prefix_for_name

	// Testing value
	// anouncement_name = "testrouteadv"

	// {"namespace":"system", "metadata":{"name":"testrouteadv", "description":"testrouteadv","disable":false}, "spec":{"prefix":"206.130.12.0/24", "expiration_never":{},"activation_announce":{} }}
	prefix_announce_query := map[string]interface{}{
		"namespace": "system",
		"metadata": map[string]interface{}{
			"name":        anouncement_name,
			"description": anouncement_name,
			"disable":     false,
		},
		"spec": map[string]interface{}{
			"prefix":              prefix,
			"expiration_never":    map[string]interface{}{},
			"activation_announce": map[string]interface{}{},
		},
	}

	if withdrawal {
		method = http.MethodDelete

		// We need to specify announcement name
		url_path = "/api/infraprotect/namespaces/system/infraprotect_internet_prefix_advertisements/" + anouncement_name

		// Just empty query body
		prefix_announce_query = map[string]interface{}{}
	}

	prefix_announce_json, err := json.Marshal(prefix_announce_query)

	if err != nil {
		return fmt.Errorf("Cannot encode prefix announce message to JSON: %v", err)
	}

	fast_logger.Printf("Prefix announce message: %v", string(prefix_announce_json))

	fast_logger.Printf("Sending query to URL: %s", f5_xc_api_url+url_path)

	req, err := http.NewRequest(method, f5_xc_api_url+url_path, bytes.NewReader(prefix_announce_json))

	if err != nil {
		return fmt.Errorf("Cannot create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("cache-control", "no-cache")

	res, err := http_client.Do(req)

	if err != nil {
		return fmt.Errorf("Cannot make POST query: %v", err)
	}

	response_body_raw, _ := ioutil.ReadAll(res.Body)

	response_body := string(response_body_raw)

	// Some error codes are common and we handle them here
	if res.StatusCode == 400 {
		return fmt.Errorf("API returned code 400: %+v Response: %s", res, response_body)
	} else if res.StatusCode == 403 {
		// May be returned when we have no permissions for prefix
		return fmt.Errorf("403 response, access forbidden. Response: %s", response_body)
	}

	// Other response codes depend on announce or withdrawal
	if withdrawal {

		if res.StatusCode == 404 {
			// We know it happens when we try to withdraw announce which does not exist
			return fmt.Errorf("404 response code, advertisement may not exists. Response: %s", response_body)
		} else if res.StatusCode == 200 {
			// It returns empty JSON document in this case
			// It mean successful withdrawal
			return nil
		} else {
			return fmt.Errorf("Unknown response code. Response body: %v Response code: %d", string(response_body), res.StatusCode)
		}

	} else {
		if res.StatusCode == 409 {
			return fmt.Errorf("409, conflict, apparently announce is active already. Response: %s", response_body)
		} else if res.StatusCode == 200 {
			// For announcement 200 means successful announce

			/*
			   {
			     "metadata": {
			       "name": "fastnetmon-206-130-12-0-24",
			       "namespace": "system",
			       "labels": {
			       },
			       "annotations": {
			       },
			       "description": "fastnetmon-206-130-12-0-24",
			       "disable": false
			     },
			     "system_metadata": {
			       "uid": "0a168085-1a74-4fbe-bde1-65aff07d1dfd",
			       "creation_timestamp": "2023-07-03T17:03:48.212594070Z",
			       "deletion_timestamp": null,
			       "modification_timestamp": null,
			       "initializers": null,
			       "finalizers": [
			       ],
			       "tenant": "f5-neteng-foymhriv",
			       "creator_class": "prism",
			       "creator_id": "ta2-neteng-system-admin-hcggqodh@volterracredentials.io",
			       "object_index": 0,
			       "owner_view": null,
			       "labels": {
			       }
			     },
			     "spec": {
			       "prefix": "206.130.12.0/24",
			       "expiration_never": {

			       },
			       "activation_announce": {

			       }
			     }
			   }
			*/

		} else {
			return fmt.Errorf("Unknown response code. Response body: %v Response code: %d", string(response_body), res.StatusCode)
		}
	}

	return nil
}

// Announce route
func f5_announce_route(auth_token string, prefix string, withdrawal bool) error {
	// Set reasonable timeout
	http_client := &http.Client{
		Timeout: time.Second * 60,
	}

	prefix_announce_query := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "string",
			"attributes": map[string]interface{}{
				"prefix":  prefix,
				"comment": "Announced by FastNetMon Advanced",
			},
		},
	}

	prefix_announce_json, err := json.Marshal(prefix_announce_query)

	if err != nil {
		return fmt.Errorf("Cannot encode prefix announce message to JSON: %v", err)
	}

	fast_logger.Printf("Prefix announce message: %v", string(prefix_announce_json))

	method := http.MethodPost

	if withdrawal {
		method = http.MethodDelete
	}

	req, err := http.NewRequest(method, f5_api_url+"routes", bytes.NewReader(prefix_announce_json))

	if err != nil {
		return fmt.Errorf("Cannot create request: %v", err)
	}

	req.Header.Set("X-Authorization-Token", auth_token)
	req.Header.Set("Content-Type", "application/json")

	res, err := http_client.Do(req)

	if err != nil {
		return fmt.Errorf("Cannot make POST query: %v", err)
	}

	// We have different expected response codes for announce and withdrawal
	expected_status_code := 201

	if withdrawal {
		expected_status_code = 200
	}

	if res.StatusCode == expected_status_code {
		res_body, err := ioutil.ReadAll(res.Body)

		if err != nil {
			return fmt.Errorf("Cannot read body for successful answer: %v", err)
		}

		// Successful announcement response:
		/*
			{"data":{"type":"routes","id":6612,"attributes":{"action":"announce","ttl":0,"nexthop":"172.16.98.6","subnet":"91.217.176.0/24","name":"17XXXXXXXXXXXXXXXXXXXXXXXXXXXXbb","created_at":"2022-10-18T11:58:54.756Z","comment":"Announced by FastNetMon Advanced"},"meta":{"message":"Your route has been queued for advertisement."}}}
		*/

		// Successful withdrawal response:
		/*

			{"data":{"type":"routes","id":6613,"attributes":{"action":"withdraw","ttl":0,"nexthop":"172.16.98.6","subnet":"91.217.176.0/24","name":"17XXXXXXXXXXXXXXXXXXXXXXXXXXXXbb","created_at":"2022-10-18T12:02:02.866Z","comment":"Withdrawing 91.217.176.0/24"},"meta":{"message":"Your route has been queued for withdrawal."}}}

		*/

		//
		fast_logger.Printf("Successful prefix announce: %s", string(res_body))

		return nil
	} else {
		// According to documentation it can be 400 and 401
		// But in reality we observed 500 and 403
		// We ignore error as we OK with empty body

		// Failed announce with code 403
		/*

			{ "error":"The requested prefix 91.217.176.0/24 is already being advertised by F5 Silverline. Please  reference the currently advertised prefixes in the Route Originate  section of the F5 Silverline Portal: https://portal.f5silverline.com or  use the API endpoint: GET /api/v1/routes/advertised" }

		*/

		// Failed withdrawal with code 403
		/*

			{"error":"The requested prefix 91.217.176.0/24 is not currently being advertised by F5 Silverline. Please reference the currently advertised prefixes in the Route Originate section of the F5 Silverline Portal: https://portal.f5silverline.com or use the API endpoint: GET  /api/v1/routes/advertised"}

		*/

		res_body, _ := ioutil.ReadAll(res.Body)

		return fmt.Errorf("Announce failed with code %d. Body: %s", res.StatusCode, res_body)
	}

}

// Announce route
func path_announce_route(auth_token string, prefix string, withdrawal bool) error {
	// Set reasonable timeout
	http_client := &http.Client{
		Timeout: time.Second * 60,
	}

	method := http.MethodPost

	if withdrawal {
		method = http.MethodDelete
	}

	// We use empty query
	req, err := http.NewRequest(method, path_api_url+"diversions/"+prefix, strings.NewReader(""))

	if err != nil {
		return fmt.Errorf("Cannot create request: %v", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization", "Bearer "+auth_token)

	res, err := http_client.Do(req)

	if err != nil {
		return fmt.Errorf("Cannot make POST query: %v", err)
	}

	if res.StatusCode == 202 {
		res_body, err := ioutil.ReadAll(res.Body)

		if err != nil {
			return fmt.Errorf("Cannot read body for successful answer: %v", err)
		}

		// In case of success their API response this way:
		// {"acknowledged":true}

		fast_logger.Printf("Successful announce response: %+v", res)
		fast_logger.Printf("Successful announce response body: %v", string(res_body))

		return nil
	} else {
		// According to documentation it can be 401, 404, 422
		// We ignore error as we OK with empty body
		res_body, _ := ioutil.ReadAll(res.Body)

		return fmt.Errorf("Auth failed with code %d. Body: %s", res.StatusCode, res_body)
	}
}

// Auth on Path.net
func path_auth(username string, password string, fake_auth bool) (string, error) {
	// Set reasonable timeout
	http_client := &http.Client{
		Timeout: time.Second * 60,
	}

	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)

	url_encoded_query := data.Encode()

	// Do not print it as it has sensitive information
	// fast_logger.Printf("Encoded query: %v", string(url_encoded_query))

	req, err := http.NewRequest(http.MethodPost, path_api_url+"token", strings.NewReader(url_encoded_query))

	if err != nil {
		return "", fmt.Errorf("Cannot create request: %v", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := http_client.Do(req)

	if err != nil {
		return "", fmt.Errorf("Cannot make POST query: %v", err)
	}

	type PathAuthResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}

	authRes := PathAuthResponse{}

	if fake_auth {
		fake_successfull_auth_response := `{
  "access_token": "token",
  "token_type": "token_type" 
  }
`
		err = json.Unmarshal([]byte(fake_successfull_auth_response), &authRes)

		if err != nil {
			return "", fmt.Errorf("Cannot unmarshal JSON data: %v", err)
		}

		return authRes.AccessToken, nil
	}

	if res.StatusCode == 200 {
		res_body, err := ioutil.ReadAll(res.Body)

		if err != nil {
			return "", fmt.Errorf("Cannot read body for successful answer: %v", err)
		}

		fast_logger.Printf("Successful auth response: %+v", res)
		fast_logger.Printf("Successful auth response body: %v", string(res_body))

		err = json.Unmarshal(res_body, &authRes)

		if err != nil {
			return "", fmt.Errorf("Cannot unmarshal JSON data: %v", err)
		}

		auth_token := authRes.AccessToken

		if auth_token == "" {
			return "", fmt.Errorf("Empty token")
		}

		return auth_token, nil

	} else {
		// According to documentation it can be 401 or 422
		// We ignore error as we OK with empty body
		res_body, _ := ioutil.ReadAll(res.Body)

		return "", fmt.Errorf("Auth failed with code %d. Body: %s", res.StatusCode, res_body)
	}

}

// Auth on F5 Silverline
func f5_auth(email string, password string, fake_auth bool) (string, error) {

	// Set reasonable timeout
	http_client := &http.Client{
		Timeout: time.Second * 60,
	}

	auth_query := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "string",
			"attributes": map[string]interface{}{
				"email":    email,
				"password": password,
			},
		},
	}

	auth_query_json, err := json.Marshal(auth_query)

	if err != nil {
		return "", fmt.Errorf("Cannot encode authentication message to JSON: %v", err)
	}

	// Do not print it as it has sensitive information
	// fast_logger.Printf("Auth message: %v", string(auth_query_json))

	req, err := http.NewRequest(http.MethodPost, f5_api_url+"sessions", bytes.NewReader(auth_query_json))

	if err != nil {
		return "", fmt.Errorf("Cannot create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := http_client.Do(req)

	if err != nil {
		return "", fmt.Errorf("Cannot make POST query: %v", err)
	}

	// Fake structure for testing without live API connection
	// Example in their documentation is incorrect, I got this one from real API
	fake_successful_auth_answer := `{"data":{"id":null,"type":"sessions","attributes":{"auth_token":"17c346a69336039e6bc44cf62e6a14bb"}}}`

	type AuthResponseAttributes struct {
		AuthToken string `json:"auth_token"`
	}

	type AuthResponseDataField struct {
		// We ignore Id field as type of it is not very clear
		Type       string                 `json:"type"`
		Attributes AuthResponseAttributes `json:"attributes"`
	}

	type AuthResponseData struct {
		DataField AuthResponseDataField `json:"data"`
	}

	authRes := AuthResponseData{}

	if fake_auth {
		err = json.Unmarshal([]byte(fake_successful_auth_answer), &authRes)

		if err != nil {
			return "", fmt.Errorf("Cannot decode example auth response: %v", err)
		}

		return authRes.DataField.Attributes.AuthToken, nil
	}

	if res.StatusCode == 201 {
		res_body, err := ioutil.ReadAll(res.Body)

		if err != nil {
			return "", fmt.Errorf("Cannot read body for successful answer: %v", err)
		}

		fast_logger.Printf("Successful auth response: %+v", res)
		fast_logger.Printf("Successful auth response body: %v", string(res_body))

		err = json.Unmarshal(res_body, &authRes)

		if err != nil {
			return "", fmt.Errorf("Cannot unmarshal JSON data: %v", err)
		}

		auth_token := authRes.DataField.Attributes.AuthToken

		if auth_token == "" {
			return "", fmt.Errorf("Empty token")
		}

		return auth_token, nil

	} else {
		// According to documentation it can be 400 and 401
		// But in reality we observed 500
		// We ignore error as we OK with empty body
		res_body, _ := ioutil.ReadAll(res.Body)

		return "", fmt.Errorf("Auth failed with code %d. Body: %s", res.StatusCode, res_body)
	}
}
