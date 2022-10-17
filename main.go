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

	// Fake structure for testing without live API connection
	fake_successful_auth_answer := `
{
  "CustomerToken": {
    "value": {
      "data": {
        "id": null,
        "type": "sessions",
        "attributes": {
          "auth_token": "sampletoken"
        }
      }
    }
  }
}
`
	_ = fake_successful_auth_answer

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

	type AuthResponseValue struct {
		Value AuthResponseData `json:"value"`
	}

	// Structure for auth response
	type AuthResponse struct {
		CustomerToken AuthResponseValue `json:"CustomerToken"`
	}

	authRes := AuthResponse{}

	if res.StatusCode == 201 {
		res_body, err := ioutil.ReadAll(res.Body)

		if err != nil {
			log.Fatalf("Cannot read body for successful answer: %v", err)
		}

		log.Printf("Successful auth: %+v", res_body)

		err = json.Unmarshal(res_body, &authRes)

		if err != nil {
			log.Fatalf("Cannot unmarshal JSON data: %v", err)
		}

		log.Fatalf("Successfully retrieved auth token: %+v", authRes.CustomerToken.Value.DataField.Attributes.AuthToken)

	} else {
		// According to documentation it can be 400 and 401
		// But in reality we observed 500
		// We ignore error as we OK with empty body
		res_body, _ := ioutil.ReadAll(res.Body)

		log.Fatalf("Auth failed with code %d. Body: %s", res.StatusCode, res_body)
	}
}
