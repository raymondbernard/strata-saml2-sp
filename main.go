package main


import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"time"
	"net/url"

)



func Env(key string, fallback string) string {
	value, exists := os.LookupEnv(key)
	if exists {
		return value
	}
	return fallback
}

func LoadConfig() samlsp.Options {
	samlOptions := samlsp.Options{
		AllowIDPInitiated: true,
		Logger:            log.WithField("component", "saml-lib"),
	}

	samlOptions.EntityID = Env("SP_ENTITY_ID", "saml-test-sp")

	metadataURL, metadataURLexists := os.LookupEnv("SP_METADATA_URL")
	if metadataURLexists {
		log.Debugf("Will attempt to load metadata from %s", metadataURL)
		idpMetadataURL, err := url.Parse(metadataURL)
		if err != nil {
			panic(err)
		}
		samlOptions.IDPMetadataURL = idpMetadataURL
	} else {
		ssoURL := Env("SP_SSO_URL", "")
		binding := Env("SP_SSO_BINDING", saml.HTTPPostBinding)
		samlOptions.IDPMetadata = &saml.EntityDescriptor{
			EntityID: samlOptions.EntityID,
			IDPSSODescriptors: []saml.IDPSSODescriptor{
				{
					SingleSignOnServices: []saml.Endpoint{
						{
							Binding:  binding,
							Location: ssoURL,
						},
					},
				},
			},
		}
		if singingCert := Env("SP_SIGNING_CERT", ""); singingCert != "" {
			samlOptions.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors = []saml.KeyDescriptor{
				{
					Use: "singing",
					KeyInfo: saml.KeyInfo{
						Certificate: singingCert,
					},
				},
			}
		}
		
	}

	defaultURL := "http://localhost:9009"
	if _, ok := os.LookupEnv("SP_SSL_CERT"); ok {
		defaultURL = "https://localhost:9009"
	}
	rootURL := Env("SP_ROOT_URL", defaultURL)
	url, err := url.Parse(rootURL)
	if err != nil {
		panic(err)
	}
	samlOptions.URL = *url

	priv, pub := Generate(fmt.Sprintf("localhost,%s", url.Hostname()))
	samlOptions.Key = priv
	samlOptions.Certificate = pub
	log.Debugf("Configuration Optons: %+v", samlOptions)
	return samlOptions
}


func Generate(host string) (*rsa.PrivateKey, *x509.Certificate) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames: strings.Split(host, ","),
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	cert, _ := x509.ParseCertificate(derBytes)

	return priv, cert
}




func hello(w http.ResponseWriter, r *http.Request) {
	s := samlsp.SessionFromContext(r.Context())
	if s == nil {
		http.Error(w, "No Session", http.StatusInternalServerError)
		return
	}
	sa, ok := s.(samlsp.SessionWithAttributes)
	if !ok {
		http.Error(w, "Session has no attributes", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	data, err := json.MarshalIndent(sa, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	fmt.Fprint(w, "hello :)")
}

func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.WithField("remoteAddr", r.RemoteAddr).WithField("method", r.Method).Info(r.URL)
		handler.ServeHTTP(w, r)
	})
}


func RunServer() {
	config := LoadConfig()

	samlSP, err := samlsp.New(config)

	if err != nil {
		panic(err)
	}
	http.Handle("/", samlSP.RequireAccount(http.HandlerFunc(hello)))
	http.Handle("/saml/", samlSP)
	http.HandleFunc("/health", health)

	listen := Env("SP_BIND", "localhost:9009")
	log.Infof("Server listening on '%s'", listen)
	log.Infof("ACS URL is '%s'", samlSP.ServiceProvider.AcsURL.String())

	if _, set := os.LookupEnv("SP_SSL_CERT"); set {
		// SP_SSL_CERT set, so we run SSL mode
		err := http.ListenAndServeTLS(listen, os.Getenv("SP_SSL_CERT"), os.Getenv("SP_SSL_KEY"), logRequest(http.DefaultServeMux))
		if err != nil {
			panic(err)
		}
	} else {
		err = http.ListenAndServe(listen, logRequest(http.DefaultServeMux))
		if err != nil {
			panic(err)
		}
	}
}



func main() {
	log.SetLevel(log.DebugLevel)

	RunServer()

}
