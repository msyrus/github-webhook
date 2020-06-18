package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sync"

	"gopkg.in/yaml.v3"
)

var secret string
var scripts map[string][]string
var mu sync.Mutex

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		log.Fatalln("config is required")
	}

	fd, err := os.Open(args[0])
	if err != nil {
		log.Fatalln(err)
	}

	cfg := struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Secret   string `yaml:"secret"`
		Settings []struct {
			Refs    []string `yaml:"refs"`
			Scripts []string `yaml:"scripts"`
		} `yaml:"settings"`
	}{}

	if err := yaml.NewDecoder(fd).Decode(&cfg); err != nil {
		log.Fatalln(err)
	}

	secret = cfg.Secret
	scripts = map[string][]string{}
	for _, s := range cfg.Settings {
		for _, r := range s.Refs {
			scripts[r] = append(scripts[r], s.Scripts...)
		}
	}

	fmt.Printf("Listening on %s:%d\n", cfg.Host, cfg.Port)
	http.ListenAndServe(fmt.Sprintf("%s:%d", cfg.Host, cfg.Port), http.HandlerFunc(handleEvents))
}

func verifySignature(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if secret == "" {
			next.ServeHTTP(w, r)
			return
		}

		sign := r.Header.Get("X-Hub-Signature")
		if sign == "" {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		r.Body.Close()

		mac := hmac.New(sha1.New, []byte(secret))
		mac.Write(body)
		if !hmac.Equal([]byte(sign[5:]), mac.Sum(nil)) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		next.ServeHTTP(w, r)
	})
}

func handlePanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Println(err)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

type payload struct {
	Ref string
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	pld := payload{}
	if err := json.NewDecoder(r.Body).Decode(&pld); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	scrpts := scripts[pld.Ref]
	log.Println("Executing scripts for", pld.Ref)
	for _, scrpt := range scrpts {
		log.Println("Running", scrpt)
		cmd := exec.Command(scrpt)
		if err := cmd.Run(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}
