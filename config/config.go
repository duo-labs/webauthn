package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

// Config represents the configuration information.
type Config struct {
	DBName         string `json:"db_name"`
	DBPath         string `json:"db_path"`
	MigrationsPath string `json:"migrations_prefix"`
	HostAddress    string `json:"host_address"`
	HostPort       string `json:"host_port"`
	HasProxy       bool   `json:"has_proxy"`
}

// Conf contains the initialized configuration struct
var Conf Config
var Version = "0.3"

func LoadConfig(filepath string) {
	// Get the config file
	config_file, err := ioutil.ReadFile(filepath)
	if err != nil {
		fmt.Printf("File error: %v\n", err)
	}
	json.Unmarshal(config_file, &Conf)
	// Choosing the migrations directory based on the database used.
	Conf.MigrationsPath = Conf.MigrationsPath + Conf.DBName
}
