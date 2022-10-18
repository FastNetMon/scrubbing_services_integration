package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Configuration struct {
	// f5 or path
	ProviderName  string `json:"provider_name"`
	ExamplePrefix string `json:"example_prefix"`

	// F5 Silverline credentials
	F5Email    string `json:"f5_email"`
	F5Password string `json:"f5_password"`

	// Path credentials
	PathUsername string `json:"path_username"`
	PathPassword string `json:"path_password"`
}

var f5_api_url string = "https://portal.f5silverline.com/api/v1/"

var path_api_url string = "https://api.path.net/"

func main() {
	conf := Configuration{}

	configuration_file_path := "/etc/fastnetmon_scrubbing_services_integration.json"

	conf_file_data, err := ioutil.ReadFile(configuration_file_path)

	if err != nil {
		log.Fatalf("Cannot open configuration file: %v", configuration_file_path)
	}

	err = json.Unmarshal([]byte(conf_file_data), &conf)

	if err != nil {
		log.Fatalf("Cannot decode configuration file %s: %v", configuration_file_path, err)
	}

	if conf.ProviderName == "f5" {

		if conf.F5Email == "" {
			log.Fatal("Please set f5_email field in configuration")
		}

		if conf.F5Password == "" {
			log.Fatal("Please set f5_password field in configuration")
		}

		if conf.ExamplePrefix == "" {
			log.Fatal("Please set example_prefix in configuration")
		}

		fake_auth := false

		auth_token, err := f5_auth(conf.F5Email, conf.F5Password, fake_auth)

		if err != nil {
			log.Fatalf("Auth failed: %v", err)
		}

		log.Printf("Successful auth with token: %v", auth_token)

		err = f5_announce_route(auth_token, conf.ExamplePrefix, false)

		if err != nil {
			log.Printf("Cannot announce prefix: %v with error: %v", conf.ExamplePrefix, err)
			// We do not stop here as we need to withdraw it even if something happened during withdrawal
		}

		err = f5_announce_route(auth_token, conf.ExamplePrefix, true)

		if err != nil {
			log.Printf("Cannot withdraw prefix: %v with error: %v", conf.ExamplePrefix, err)
			// We do not stop here as we need to withdraw it even if something happened during withdrawal
		}

	} else if conf.ProviderName == "path" {
		if conf.PathUsername == "" {
			log.Fatal("Please set path_username field in configuration")
		}

		if conf.PathPassword == "" {
			log.Fatal("Please set path_password field in configuration")
		}

		if conf.ExamplePrefix == "" {
			log.Fatal("Please set example_prefix in configuration")
		}

	} else {
		log.Fatalf("Unknown provider name, we support only 'f5' or 'path': %s", conf.ProviderName)
	}
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

	log.Printf("Prefix announce message: %v", string(prefix_announce_json))

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

		log.Printf("Successful prefix announce: %s", string(res_body))

		return nil
	} else {
		// According to documentation it can be 400 and 401
		// But in reality we observed 500
		// We ignore error as we OK with empty body
		res_body, _ := ioutil.ReadAll(res.Body)

		return fmt.Errorf("Auth failed with code %d. Body: %s", res.StatusCode, res_body)
	}

}

// Auth on Path.net
func path_auth(username string, password string) (string, error) {
	// Set reasonable timeout
	http_client := &http.Client{
		Timeout: time.Second * 60,
	}

	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)

	url_encoded_query := data.Encode()

	log.Printf("Encoded query: %v", string(url_encoded_query))

	req, err := http.NewRequest(http.MethodPost, path_api_url+"token", strings.NewReader(url_encoded_query))

	if err != nil {
		return "", fmt.Errorf("Cannot create request: %v", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := http_client.Do(req)

	if err != nil {
		return "", fmt.Errorf("Cannot make POST query: %v", err)
	}

	if res.StatusCode == 200 {
		res_body, err := ioutil.ReadAll(res.Body)

		if err != nil {
			return "", fmt.Errorf("Cannot read body for successful answer: %v", err)
		}

		log.Printf("Successful auth response: %+v %v", res)
		log.Printf("Successful auth response body: %v", string(res_body))

		type PathAuthResponse struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
		}

		authRes := PathAuthResponse{}

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

	log.Printf("Auth message: %v", string(auth_query_json))

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

		log.Printf("Successful auth response: %+v %v", res)
		log.Printf("Successful auth response body: %v", string(res_body))

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
