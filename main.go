package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

var (
	nonsense []byte
	rt       *http3.RoundTripper
	cl       *http.Client
)

func main() {
	defer saveProfile("heap", "memprofile")
	defer saveProfile("goroutine", "goprofile")

	// Make up nonsense data
	nonsense = make([]byte, 65536)
	io.ReadFull(rand.Reader, nonsense)

	// Generate certificate
	rootCA, cakey, err := generateCA()
	if err != nil {
		log.Fatal(err)
	}
	cert, certKey, err := generateCert("localhost", rootCA, cakey)
	if err != nil {
		log.Fatal(err)
	}

	// Set up server
	tlsConf := &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  certKey,
	}}}
	srv := &http3.Server{
		Addr:      ":8443",
		TLSConfig: tlsConf,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(nonsense)
		}),
	}
	go srv.ListenAndServe()

	// Set up client
	certPool := x509.NewCertPool()
	certPool.AddCert(rootCA)
	rt = &http3.RoundTripper{TLSClientConfig: &tls.Config{RootCAs: certPool}}
	defer rt.Close()
	cl = &http.Client{Transport: rt}

	// Do some tests
	goaway := time.Now().Add(20 * time.Second)
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(goaway) {
				if err := Get(); err != nil {
					log.Println(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func Get() error {
	resp, err := cl.Get("https://localhost:8443")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	return err
}
