package domain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

const (
	reverseWhoisURI = "https://reverse-whois.whoisxmlapi.com/api/v2"
)

type reverseWhoisResponse struct {
	NextPageSearchAfter interface{} `json:"nextPageSearchAfter"`
	DomainsCount        int         `json:"domainsCount"`
	DomainsList         []string    `json:"domainsList"`
}

type reverseWhoisParams struct {
	ApiKey           string `json:"apiKey"`
	SearchType       string `json:"searchType,omitempty"`
	Mode             string `json:"mode,omitempty"`
	Punycode         bool   `json:"punycode,omitempty"`
	BasicSearchTerms struct {
		Include []string `json:"include"`
		Exclude []string `json:"exclude,omitempty"`
	} `json:"basicSearchTerms"`
}

type Registrant struct {
	Name         string `json:"name"`
	Organization string `json:"organization"`
	Street1      string `json:"street1"`
	Street2      string `json:"street2"`
	Street3      string `json:"street3"`
	Street4      string `json:"street4"`
	City         string `json:"city"`
	State        string `json:"state"`
	PostalCode   string `json:"postalCode"`
	Country      string `json:"country"`
	CountryCode  string `json:"countryCode"`
	Email        string `json:"email"`
	Telephone    string `json:"telephone"`
	TelephoneExt string `json:"telephoneExt"`
	Fax          string `json:"fax"`
	FaxExt       string `json:"faxExt"`
	RawText      string `json:"rawText"`
	Unparsable   string `json:"unparsable"`
}

type WhoisData struct {
	DomainName            string    `json:"domainName"`
	UpdatedDateNormalized string    `json:"updatedDateNormalized"`
	ExpiresDateNormalized string    `json:"expiresDateNormalized"`
	CreatedDate           time.Time `json:"createdDate"`
	UpdatedDate           time.Time `json:"updatedDate"`
	ExpiresDate           time.Time `json:"expiresDate"`
	RegistrarName         string    `json:"registrarName"`
	RegistrarIANAID       string    `json:"registrarIANAID"`
	Status                string    `json:"status"`
	RawText               string    `json:"rawText"`
	ParseCode             int       `json:"parseCode"`
	Registrant            `json:"registrant"`
	AdministrativeContact struct {
		Name         string `json:"name"`
		Organization string `json:"organization"`
		Street1      string `json:"street1"`
		Street2      string `json:"street2"`
		Street3      string `json:"street3"`
		Street4      string `json:"street4"`
		City         string `json:"city"`
		State        string `json:"state"`
		PostalCode   string `json:"postalCode"`
		Country      string `json:"country"`
		CountryCode  string `json:"countryCode"`
		Email        string `json:"email"`
		Telephone    string `json:"telephone"`
		TelephoneExt string `json:"telephoneExt"`
		Fax          string `json:"fax"`
		FaxExt       string `json:"faxExt"`
		RawText      string `json:"rawText"`
		Unparsable   string `json:"unparsable"`
	} `json:"administrativeContact"`
	TechnicalContact struct {
		Name         string `json:"name"`
		Organization string `json:"organization"`
		Street1      string `json:"street1"`
		Street2      string `json:"street2"`
		Street3      string `json:"street3"`
		Street4      string `json:"street4"`
		City         string `json:"city"`
		State        string `json:"state"`
		PostalCode   string `json:"postalCode"`
		Country      string `json:"country"`
		CountryCode  string `json:"countryCode"`
		Email        string `json:"email"`
		Telephone    string `json:"telephone"`
		TelephoneExt string `json:"telephoneExt"`
		Fax          string `json:"fax"`
		FaxExt       string `json:"faxExt"`
		RawText      string `json:"rawText"`
		Unparsable   string `json:"unparsable"`
	} `json:"technicalContact"`
	BillingContact struct {
		Name         string `json:"name"`
		Organization string `json:"organization"`
		Street1      string `json:"street1"`
		Street2      string `json:"street2"`
		Street3      string `json:"street3"`
		Street4      string `json:"street4"`
		City         string `json:"city"`
		State        string `json:"state"`
		PostalCode   string `json:"postalCode"`
		Country      string `json:"country"`
		CountryCode  string `json:"countryCode"`
		Email        string `json:"email"`
		Telephone    string `json:"telephone"`
		TelephoneExt string `json:"telephoneExt"`
		Fax          string `json:"fax"`
		FaxExt       string `json:"faxExt"`
		RawText      string `json:"rawText"`
		Unparsable   string `json:"unparsable"`
	} `json:"billingContact"`
	ZoneContact struct {
		Name         string `json:"name"`
		Organization string `json:"organization"`
		Street1      string `json:"street1"`
		Street2      string `json:"street2"`
		Street3      string `json:"street3"`
		Street4      string `json:"street4"`
		City         string `json:"city"`
		State        string `json:"state"`
		PostalCode   string `json:"postalCode"`
		Country      string `json:"country"`
		CountryCode  string `json:"countryCode"`
		Email        string `json:"email"`
		Telephone    string `json:"telephone"`
		TelephoneExt string `json:"telephoneExt"`
		Fax          string `json:"fax"`
		FaxExt       string `json:"faxExt"`
		RawText      string `json:"rawText"`
		Unparsable   string `json:"unparsable"`
	} `json:"zoneContact"`
	Header             string    `json:"header"`
	Footer             string    `json:"footer"`
	StrippedText       string    `json:"strippedText"`
	ContactEmail       string    `json:"contactEmail"`
	DomainAvailability string    `json:"domainAvailability"`
	DomainNameExt      string    `json:"domainNameExt"`
	EstimatedDomainAge int       `json:"estimatedDomainAge"`
	Ips                []string  `json:"ips"`
	Custom1FieldName   string    `json:"custom1FieldName"`
	Custom1FieldValue  string    `json:"custom1FieldValue"`
	Custom2FieldName   string    `json:"custom2FieldName"`
	Custom2FieldValue  string    `json:"custom2FieldValue"`
	Custom3FieldName   string    `json:"custom3FieldName"`
	Custom3FieldValue  string    `json:"custom3FieldValue"`
	DataError          string    `json:"dataError"`
	LastUpdated        time.Time `json:"lastRanWhois,omitempty"`
}

func (w *WhoisXMLClient) Query(ctx context.Context, domain string) (*WhoisData, error) {
	rec, resp, err := w.WhoisService.Data(ctx, domain)
	if err != nil {
		return nil, err
	}
	fmt.Println(resp.StatusCode)
	f, _ := os.Create("whoisrec.json")
	defer f.Close()
	data, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	_, err = f.Write(data)
	if err != nil {
		return nil, err
	}
	type T struct {
		WhoisData `json:"WhoisRecord"`
	}
	wd := &T{}
	err = json.NewDecoder(bytes.NewReader(resp.Body)).Decode(wd)
	if err != nil {
		return nil, err
	}

	wd.LastUpdated = time.Now()
	return &wd.WhoisData, nil
}

func (w *WhoisXMLClient) QueryReverse(ctx context.Context, registrantName string) ([]string, error) {
	if registrantName == "" || registrantName == "Not Disclosed" {
		return nil, fmt.Errorf("invalid registrant name, '%s'", registrantName)
	}
	rParams := reverseWhoisParams{
		ApiKey: w.apikey,
		Mode:   "purchase",
		BasicSearchTerms: struct {
			Include []string `json:"include"`
			Exclude []string `json:"exclude,omitempty"`
		}{
			Include: []string{registrantName},
		},
	}
	data, err := json.Marshal(rParams)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", reverseWhoisURI, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got non-200 status code: %d", resp.StatusCode)
	}

	rData := reverseWhoisResponse{}
	err = json.NewDecoder(resp.Body).Decode(&rData)
	if err != nil {
		return nil, err
	}
	return rData.DomainsList, nil
}

func (d *Domain) GetWhoisData() error {
	wd, err := client.Whois.Query(context.Background(), d.DomainName)
	if err != nil {
		return err
	}
	d.Whois = wd
	return nil
}

func (d *Domain) GetReverseWhoisData() error {
	rwd, err := client.Whois.QueryReverse(context.Background(), d.Whois.Registrant.Organization)
	if err != nil {
		return err
	}
	d.LastRanReverseWhois = time.Now()
	md := []MatchedDomain{}
	for _, dom := range rwd {
		md = append(
			md, MatchedDomain{
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
				DomainName: dom,
			},
		)
	}
	return nil
}