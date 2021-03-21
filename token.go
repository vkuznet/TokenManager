package TokenManager

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
)

// ReadToken reads either given token file or string and return the token
func ReadToken(r string) string {
	if _, err := os.Stat(r); err == nil {
		b, e := ioutil.ReadFile(r)
		if e != nil {
			log.Fatalf("Unable to read data from file: %s, error: %s", r, e)
		}
		return strings.Replace(string(b), "\n", "", -1)
	}
	return r
}

// TokenRecord represents token record
type TokenRecord struct {
	AccessToken        string `json:"access_token"`
	AccessTokenExpire  int64  `json:"expires_in"`
	RefreshToken       string `json:"refresh_token"`
	RefreshTokenExpire int64  `json:"refresh_expires_in"`
	IdToken            string `json:"id_token"`
}

// Renew token
func Renew(uri, token, rootCAs string, verbose int) TokenRecord {
	t := ReadToken(token)
	if verbose > 1 {
		log.Printf("renew %s\ninput token : %s\noutput token: %s\n", uri, token, t)
	}
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", t))
	req.Header.Set("Accept", "application/json")
	if verbose > 0 {
		dump, err := httputil.DumpRequestOut(req, true)
		if err == nil {
			log.Println("request: ", string(dump))
		}
	}
	// get http client
	client := &http.Client{}
	tr, err := Transport(rootCAs, verbose)
	if err == nil {
		client = &http.Client{Transport: tr}
	}
	resp, err := client.Do(req)
	if err == nil {
		if verbose > 1 {
			dump, err := httputil.DumpResponse(resp, true)
			if err == nil {
				log.Println("[DEBUG] response:", string(dump))
			}
		}
	} else {
		log.Fatal("Unable to make HTTP request", req, err)
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	var rec TokenRecord
	err = json.Unmarshal(data, &rec)
	if err != nil {
		log.Fatal(err)
	}
	return rec
}

// Transport helper function to get http transport
func Transport(rootCAs string, verbose int) (*http.Transport, error) {
	certPool := x509.NewCertPool()
	files, err := ioutil.ReadDir(rootCAs)
	if err != nil {
		msg := fmt.Sprintf("Unable to list files in '%s', error: %v\n", rootCAs, err)
		if rootCAs == "" {
			msg = fmt.Sprintf("root CAs area is not provided")
		}
		log.Printf(msg)
		return nil, errors.New(msg)
	}
	var certs bool
	for _, finfo := range files {
		fname := fmt.Sprintf("%s/%s", rootCAs, finfo.Name())
		caCert, err := ioutil.ReadFile(fname)
		if err != nil {
			if verbose > 1 {
				log.Printf("Unable to read %s\n", fname)
			}
		}
		if ok := certPool.AppendCertsFromPEM(caCert); !ok {
			if verbose > 2 {
				log.Printf("invalid PEM format while importing trust-chain: %q", fname)
			}
		}
		if verbose > 2 {
			log.Println("Load CA file", fname)
		}
		certs = true
	}
	mTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	if certs {
		mTLSConfig = &tls.Config{
			RootCAs: certPool,
		}
	}
	tr := &http.Transport{
		TLSClientConfig: mTLSConfig,
	}
	return tr, nil
}

// LoadCAs helper function loads CERN CAs
func LoadCAs(verbose int) (string, error) {
	var homeDir string
	for _, item := range os.Environ() {
		value := strings.Split(item, "=")
		if value[0] == "HOME" {
			homeDir = value[1]
			break
		}
	}
	links := []string{
		"https://cafiles.cern.ch/cafiles/certificates/CERN%20Certification%20Authority.crt",
		"https://cafiles.cern.ch/cafiles/certificates/CERN%20Certification%20Authority(1).crt",
		"https://cafiles.cern.ch/cafiles/certificates/CERN%20Root%20Certification%20Authority%202.crt",
		"https://cafiles.cern.ch/cafiles/certificates/CERN%20Grid%20Certification%20Authority.crt",
	}
	dname := fmt.Sprintf("%s/.certificates", homeDir)
	if _, err := os.Stat(dname); err != nil {
		os.Mkdir(dname, 0777)
	}
	for _, link := range links {
		arr := strings.Split(link, "/")
		fname := fmt.Sprintf("%s/.certificates/%s", homeDir, arr[len(arr)-1])
		if _, err := os.Stat(fname); err != nil {
			if verbose > 0 {
				fmt.Println("download", link)
			}
			resp, err := http.Get(link)
			if err != nil {
				return dname, err
			}
			defer resp.Body.Close()
			data, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return dname, err
			}
			err = ioutil.WriteFile(fname, []byte(data), 0777)
			if err != nil {
				return dname, err
			}
		}
	}
	return dname, nil
}
