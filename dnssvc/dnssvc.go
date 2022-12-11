package dnssvc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type DnsSvcClient struct {
	token string
}

type Services struct {
	ServiceIds []string  `json:"service_ids"`
	Zones      []ZoneRec `json:"zones"`
}

type ZoneRec struct {
	DomainId  string `json:"domain_id"`
	Name      string `json:"name"`
	ServiceId string `json:"service_id"`
}

type DNSHeader struct {
	ServiceId string               `json:"service_id"`
	Name      string               `json:"name"`
	Records   map[string]DNSRecord `json:"records"`
}

type DNSRecord struct {
	Id       string      `json:"id"`
	DomainId string      `json:"domain_id"`
	Name     string      `json:"name"`
	Type     string      `json:"type"`
	Ttl      string      `json:"ttl"`
	Prio     string      `json:"prio"`
	Content  interface{} `json:"content"`
}

func (details *DNSHeader) FindRecordByName(typ string, name string) *DNSRecord {
	if details == nil {
		return nil
	}

	if strings.HasSuffix(name, ".") {
		name = name[:len(name)-1]
	}

	for _, rec := range details.Records {
		n := rec.Name
		if strings.HasSuffix(n, ".") {
			n = n[:len(n)-1]
		}

		//fmt.Println("COMPARE: ", rec.Id, rec.Type, n, " <-> ", typ, name)
		if rec.Type == typ && n == name {
			return &rec
		}
	}
	return nil
}

func (svc *Services) GetZoneByName(name string) *ZoneRec {
	if svc == nil {
		return nil
	}
	if strings.HasSuffix(name, ".") {
		name = name[:len(name)-1]
	}
	for _, zone := range svc.Zones {
		if zone.Name == name || strings.Contains(name, zone.Name) {
			return &zone
		}
	}
	return nil
}

func (dns *DnsSvcClient) AddRecord(zone *ZoneRec, rec *DNSRecord) error {
	url := fmt.Sprintf("https://dns.services/api/service/%s/dns/%s/records", zone.ServiceId, zone.DomainId)

	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	//fmt.Println(body)

	client := &http.Client{}
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(body))
	bearer := fmt.Sprintf("Bearer %s", dns.token)
	req.Header.Set("Authorization", bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	outp, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var m map[string]interface{}
	jsonErr := json.Unmarshal(outp, &m)
	if jsonErr != nil {
		return jsonErr
	}

	fmt.Println(m)
	if m["success"] != true {
		return fmt.Errorf("POST Record API was unsuccesful")
	}

	return nil
}

func (dns *DnsSvcClient) RemoveRecord(zone *ZoneRec, rec *DNSRecord) error {
	url := fmt.Sprintf("https://dns.services/api/service/%s/dns/%s/records/%s", zone.ServiceId, zone.DomainId, rec.Id)

	client := &http.Client{}
	req, _ := http.NewRequest("DELETE", url, nil)
	bearer := fmt.Sprintf("Bearer %s", dns.token)
	req.Header.Set("Authorization", bearer)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	outp, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var m map[string]interface{}
	jsonErr := json.Unmarshal(outp, &m)
	if jsonErr != nil {
		return jsonErr
	}
	fmt.Println(m)

	if m["success"] != true {
		return fmt.Errorf("Delete Record API was unsuccesful")
	}

	return nil
}

func (dns *DnsSvcClient) GetDetails(zone *ZoneRec) (*DNSHeader, error) {
	url := fmt.Sprintf("https://dns.services/api/service/%s/dns/%s", zone.ServiceId, zone.DomainId)
	bearer := fmt.Sprintf("Bearer %s", dns.token)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", bearer)
	resp, getErr := client.Do(req)
	if getErr != nil {
		return nil, getErr
	}

	body, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil {
		return nil, readErr
	}

	//fmt.Println(string(body))

	details := DNSHeader{}
	jsonErr := json.Unmarshal(body, &details)
	if jsonErr != nil {
		return nil, jsonErr
	}

	return &details, nil
}

func (dns *DnsSvcClient) LoadDNS() (*Services, error) {
	url := "https://dns.services/api/dns"
	bearer := fmt.Sprintf("Bearer %s", dns.token)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", bearer)
	resp, getErr := client.Do(req)
	if getErr != nil {
		return nil, getErr
	}

	body, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil {
		return nil, readErr
	}

	//fmt.Println(string(body))

	services := Services{}

	jsonErr := json.Unmarshal(body, &services)
	if jsonErr != nil {
		return nil, jsonErr
	}

	return &services, nil
}

func (dns *DnsSvcClient) Login(username string, password string) error {
	url := "https://dns.services/api/login"
	data := map[string]string{
		"username": username,
		"password": password,
	}
	body, err := json.Marshal(data)
	if err != nil {
		return err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	outp, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	//fmt.Println(outp)

	var m map[string]interface{}
	jsonErr := json.Unmarshal(outp, &m)
	if jsonErr != nil {
		return jsonErr
	}

	//fmt.Println(m["token"])
	if errMsg, isErr := m["error"]; isErr {
		fmt.Println(m)
		return fmt.Errorf("Login API returned error: %s", errMsg)
	}
	dns.token = m["token"].(string)

	return nil
}
