package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type Configuration struct {
	// f5
	ProviderName string `json:"provider_name"`
	F5Email      string `json:"f5_email"`
	F5Password   string `json:"f5_password"`
}

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

	if conf.ProviderName != "f5" {
		log.Fatalf("Unknown provider name, we support only f5: %s", conf.ProviderName)
	}

	if conf.F5Email == "" {
		log.Fatal("Please set f5_email field in configuration")
	}

	if conf.F5Password == "" {
		log.Fatal("Please set f5_password field in configuration")
	}

	// Set reasonable timeout
	http_client := &http.Client{
		Timeout: time.Second * 60,
	}

	api_url := "https://portal.f5silverline.com/api/v1/"

	auth_query := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "string",
			"attributes": map[string]interface{}{
				"email":    conf.F5Email,
				"password": conf.F5Password,
			},
		},
	}

	auth_query_json, err := json.Marshal(auth_query)

	if err != nil {
		log.Fatal("Cannot encode authentication message to JSON: %v", err)
	}

	log.Printf("Auth message: %v", string(auth_query_json))

	req, err := http.NewRequest(http.MethodPost, api_url+"sessions", bytes.NewReader(auth_query_json))

	if err != nil {
		log.Fatalf("Cannot create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := http_client.Do(req)

	if err != nil {
		log.Fatalf("Cannot make POST query: %v", err)
	}

	if res.StatusCode == 201 {
		res_body, err := ioutil.ReadAll(res.Body)

		if err != nil {
			log.Fatalf("Cannot read body for successful answer: %v", err)
		}

		log.Printf("Successful auth: %s", res_body)
	} else {
		// We ignore error as we OK with empty body
		res_body, _ := ioutil.ReadAll(res.Body)

		log.Fatalf("Auth failed with code %d. Body: %s", res.StatusCode, res_body)
	}
}
