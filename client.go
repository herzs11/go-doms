package domain

import (
	"log"
	"net"
	"net/http"
	"os"
	"time"

	_ "github.com/joho/godotenv/autoload"
	"github.com/miekg/dns"
	whoisapi "github.com/whois-api-llc/whois-api-go"
)

var (
	client *Client
)

type Client struct {
	DNS   *dns.Client
	HTTP  *http.Client
	Whois *WhoisXMLClient
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second, // Maximum amount of time to wait for a dial to complete
				KeepAlive: 3 * time.Second, // Keep-alive period for an active network connection
			}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second, // Maximum amount of time to wait for a TLS handshake
			ResponseHeaderTimeout: 5 * time.Second, // Maximum amount of time to wait for a server's response headers
			ExpectContinueTimeout: 1 * time.Second, // Maximum amount of time to wait for a 100-continue response from the server
		},
		Timeout: 10 * time.Second,
	}
}

type WhoisXMLClient struct {
	*whoisapi.Client
	apikey string
}

func newWhoisXMLClient(apikey string) *WhoisXMLClient {
	return &WhoisXMLClient{
		whoisapi.NewClient(
			apikey, whoisapi.ClientParams{
				HTTPClient: newHTTPClient(),
			},
		),
		apikey,
	}
}

func init() {
	key := os.Getenv("WHOIS_XML_API_KEY")
	if key == "" {
		log.Fatal("could not get Whois api key from environment. Set the 'WHOIS_XML_API_KEY' environment variable")
	}
	client = &Client{
		DNS:   new(dns.Client),
		HTTP:  newHTTPClient(),
		Whois: newWhoisXMLClient(os.Getenv("WHOIS_XML_API_KEY")),
	}
}
