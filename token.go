package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"runtime"
	"strings"
	"time"
)

// git version of our code
var version string

// helper function to show version info
func info() string {
	goVersion := runtime.Version()
	tstamp := time.Now()
	return fmt.Sprintf("git=%s go=%s date=%s", version, goVersion, tstamp)
}

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

// helper function to print our token record
func printRecord(rec TokenRecord, verbose int) {
	if verbose > 0 {
		data, err := json.MarshalIndent(rec, "", "    ")
		if err == nil {
			log.Printf("New token record:\n%s", string(data))
		} else {
			log.Println("Unable to marshal record", err)
		}
	}
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

// main function
func main() {
	var version bool
	flag.BoolVar(&version, "version", false, "Show version")
	var verbose int
	flag.IntVar(&verbose, "verbose", 0, "verbosity level")
	var token string
	flag.StringVar(&token, "token", "", "token string or file")
	var out string
	flag.StringVar(&out, "out", "", "output file to store refreshed token")
	var uri string
	flag.StringVar(&uri, "url", "", "token URL")
	var rootCAs string
	flag.StringVar(&rootCAs, "rootCAs", "", "location of root CAs")
	var interval int
	flag.IntVar(&interval, "interval", 0, "run as daemon with given interval")
	flag.Parse()
	if version {
		fmt.Println(info())
		os.Exit(0)
	}
	if rootCAs == "" {
		dir, err := LoadCAs(verbose)
		if err != nil {
			log.Fatalf("unable to load CERN CAs: %v", err)
		}
		rootCAs = dir
	}
	if verbose > 0 {
		fmt.Println("Read CERN CAs from", rootCAs)
	}
	rurl := fmt.Sprintf("%s/token/renew", uri)
	rec := Renew(rurl, token, rootCAs, verbose)
	if out != "" {
		err := ioutil.WriteFile(out, []byte(rec.AccessToken), 0777)
		if err != nil {
			log.Fatalf("Unable to write, file: %s, error: %v\n", out, err)
		}
	}
	printRecord(rec, verbose)
	// run as daemon if requested
	if interval > 0 {
		for {
			d := time.Duration(interval) * time.Second
			time.Sleep(d)
			// get refresh token from previous record
			rtoken := rec.RefreshToken
			// renew token using our refresh token
			rec = Renew(rurl, rtoken, rootCAs, verbose)
			if out != "" {
				err := ioutil.WriteFile(out, []byte(rec.AccessToken), 0777)
				if err != nil {
					log.Fatalf("Unable to write, file: %s, error: %v\n", out, err)
				}
			}
			printRecord(rec, verbose)
		}
	}
}
