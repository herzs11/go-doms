package domain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	_ "github.com/joho/godotenv/autoload"
)

func getAPIKeyFromEnvironment() (string, error) {
	key := os.Getenv("WHOIS_XML_API_KEY")
	if key == "" {
		return "", errors.New("unable to get key from 'WHOIS_XML_API_KEY' environment variable")
	}
	return key, nil
}

func TestWhoisDomain(t *testing.T) {
	key, err := getAPIKeyFromEnvironment()
	if err != nil {
		t.Fatalf("error getting api key: %s", err.Error())
	}
	whoisClient := newWhoisXMLClient(key)
	n, err := whoisClient.Query(context.Background(), "adidas.com")
	if err != nil {
		t.Fatalf("error getting record for unum.com: %s", err.Error())
	}
	if n.DomainName != "adidas.com" {
		t.Fatalf("expected domain name %s, got %s", "adidas.com", n.DomainName)
	}
	fmt.Printf("%+v\n", n)
}

func TestReverseWhois(t *testing.T) {
	key, err := getAPIKeyFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	whoisClient := newWhoisXMLClient(key)
	doms, err := whoisClient.QueryReverse(context.Background(), "adidas.com")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(doms)
}
