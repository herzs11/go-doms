package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/temoto/robotstxt"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

type Domain struct {
	DomainName            string           `json:"domainName,omitempty"`
	CreatedAt             time.Time        `json:"createdAt,omitempty"`
	UpdatedAt             time.Time        `json:"updatedAt,omitempty"`
	NonPublicDomain       bool             `json:"nonPublicDomain,omitempty"`
	Hostname              string           `json:"hostname,omitempty"`
	Subdomain             string           `json:"subdomain,omitempty"`
	Suffix                string           `json:"suffix,omitempty"`
	SuccessfulWebLanding  bool             `json:"successfulWebLanding,omitempty"`
	WebRedirectURLFinal   string           `json:"webRedirectURLFinal,omitempty"`
	LastRanWebRedirect    time.Time        `json:"lastRanWebRedirect,omitempty"`
	LastRanDns            time.Time        `json:"lastRanDNS,omitempty"`
	LastRanCertSans       time.Time        `json:"lastRanCertSANs,omitempty"`
	LastRanSitemapParse   time.Time        `json:"lastRanSitemapParse,omitempty"`
	LastRanWhois          time.Time        `json:"LastRanWhois,omitempty"`
	LastRanReverseWhois   time.Time        `json:"LastRanReverseWhois,omitempty"`
	ARecords              []ARecord        `json:"aRecords"`
	AAAARecords           []AAAARecord     `json:"aaaaRecords"`
	MXRecords             []MXRecord       `json:"mxRecords"`
	SOARecords            []SOARecord      `json:"soaRecords"`
	Sitemaps              []*Sitemap       `json:"sitemaps"`
	WebRedirectDomains    []*MatchedDomain `json:"webRedirectDomains"`
	CertSANs              []*MatchedDomain `json:"certSANs"`
	SitemapWebDomains     []*MatchedDomain `json:"sitemapWebDomains"`
	SitemapContactDomains []*MatchedDomain `json:"sitemapContactDomains"`
	ReverseWhoisDomains   []*MatchedDomain `json:"reverseWhoisDomains"`

	CertOrgNames []string   `json:"certOrgNames,omitempty"`
	Whois        *WhoisData `json:"whoisData"`

	sitemapURLs  []string
	contactPages []string

	*robotstxt.RobotsData
}

func (d *Domain) parseDomain() error {
	dom, err := publicsuffix.ParseFromListWithOptions(
		publicsuffix.DefaultList, d.DomainName, &publicsuffix.FindOptions{IgnorePrivate: true},
	)
	if err != nil {
		return err
	}
	if dom == nil {
		d.NonPublicDomain = true
		return errors.New("Unable to parse domain from public suffix list")
	}
	d.DomainName = fmt.Sprintf("%s.%s", strings.ToLower(dom.SLD), strings.ToLower(dom.TLD))
	d.Hostname = strings.ToLower(dom.SLD)
	d.Subdomain = strings.ToLower(dom.TRD)
	d.Suffix = strings.ToLower(dom.TLD)
	d.NonPublicDomain = false
	return nil
}

func NewDomain(domainName string) (*Domain, error) {
	dn := strings.TrimSpace(domainName)
	now := time.Now()
	d := &Domain{DomainName: dn, CreatedAt: now, UpdatedAt: now}
	err := d.parseDomain()
	return d, err
}

type EnrichmentConfig struct {
	CertSans         bool      `json:"cert_sans"`
	DNS              bool      `json:"dns"`
	Sitemap          bool      `json:"sitemap"`
	WebRedirect      bool      `json:"web_redirect"`
	Whois            bool      `json:"whois"`
	ReverseWhois     bool      `json:"reverse_whois"`
	MinFreshnessDate time.Time `json:"min_freshness_date"`
}

func (d *Domain) Enrich(cfg *EnrichmentConfig) {
	if d.LastRanDns.Unix() <= cfg.MinFreshnessDate.Unix() && cfg.DNS {
		d.GetDNSRecords()
	}
	if d.LastRanWebRedirect.Unix() <= cfg.MinFreshnessDate.Unix() && cfg.WebRedirect {
		d.GetRedirectDomains()
	}
	if d.LastRanCertSans.Unix() <= cfg.MinFreshnessDate.Unix() && cfg.CertSans {
		d.GetCertSANs()
	}
	if d.LastRanSitemapParse.Unix() <= cfg.MinFreshnessDate.Unix() && cfg.Sitemap {
		d.GetDomainsFromSitemap()
	}
	if d.LastRanWhois.Unix() <= cfg.MinFreshnessDate.Unix() && cfg.Whois && client.Whois != nil {
		d.GetWhoisData()
		if d.LastRanReverseWhois.Unix() <= cfg.MinFreshnessDate.Unix() && cfg.ReverseWhois {
			d.GetReverseWhoisData()
		}
	}
}

type MatchedDomainsByStrategy struct {
	WebRedirectDomains    []string `json:"webRedirectDomains"`
	CertSANs              []string `json:"certSANs"`
	SitemapWebDomains     []string `json:"sitemapWebDomains"`
	SitemapContactDomains []string `json:"sitemapContactDomains"`
	ReverseWhoisDomains   []string `json:"reverseWhoisDomains"`
}

func (d *Domain) GetAllMatchedDomains() MatchedDomainsByStrategy {
	allDomains := MatchedDomainsByStrategy{}
	for _, w := range d.WebRedirectDomains {
		allDomains.WebRedirectDomains = append(allDomains.WebRedirectDomains, w.DomainName)
	}
	for _, c := range d.CertSANs {
		allDomains.CertSANs = append(allDomains.CertSANs, c.DomainName)
	}
	for _, s := range d.SitemapWebDomains {
		allDomains.SitemapWebDomains = append(allDomains.SitemapWebDomains, s.DomainName)
	}
	for _, c := range d.SitemapContactDomains {
		allDomains.SitemapContactDomains = append(allDomains.SitemapContactDomains, c.DomainName)
	}
	for _, c := range d.ReverseWhoisDomains {
		allDomains.ReverseWhoisDomains = append(allDomains.ReverseWhoisDomains, c.DomainName)
	}
	return allDomains
}
