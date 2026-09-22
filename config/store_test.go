package config

import "testing"

func TestStoreConfiguration(t *testing.T) {
	cfg := StoreConfig{}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Database != "sqlite" || cfg.DBPath != "data/mail.db" {
		t.Fatalf("defaults changed: %+v", cfg)
	}
	for _, tc := range []StoreConfig{
		{Database: "postgres"},
		{Database: "mysql"},
		{Database: "mysql", MySQL: MySQLConfig{User: "mail", Name: "mail", Port: -1}},
		{Database: "mysql", MySQL: MySQLConfig{User: "mail", Name: "mail", TLS: "skip-verify"}},
		{Database: "mysql", MySQL: MySQLConfig{User: "mail", Name: "../mail"}},
	} {
		if err := tc.Validate(); err == nil {
			t.Errorf("accepted invalid configuration: %+v", tc)
		}
	}
	cfg = StoreConfig{Database: "MySQL", MySQL: MySQLConfig{User: "mail", Name: "gomail"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.MySQL.Port != 3306 || cfg.MySQL.Host != "127.0.0.1" || cfg.Database != "mysql" {
		t.Fatal("missing MySQL defaults")
	}
}
