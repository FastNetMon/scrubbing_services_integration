package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
)

type Configuration struct {
	// f5
	ProviderName string `json:"provider_name"`
	F5Email      string `json:"f5_email"`
	F5Password   string `json:"f5_password"`
}

func main() {
	conf := Configuration{}

	configuration_file_path := "/etc/fastnetmon_radware.json"

	conf_file_data, err := ioutil.ReadFile(configuration_file_path)

	err = json.Unmarshal([]byte(conf_file_data), &conf)

	if err != nil {
		log.Fatalf("Cannot decode configuration file %s: %v", configuration_file_path, err)
	}

}
