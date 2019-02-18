package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/authorization"
)

const (
	defaultDockerHost = "unix:///var/run/docker.sock"
	pluginSocket      = "/run/docker/plugins/docker-image-policy.sock"
	defaultConfig     = "/etc/docker/docker-image-policy.json"
	defaultAddr       = "127.0.0.1:9166"
)

type (
	Config struct {
		Whitelist    []string `json:"whitelist"`
		Blacklist    []string `json:"blacklist"`
		DefaultAllow bool     `json:"defaultAllow"`
	}
)

// Globals
var (
	version       string
	reWhitelist   []*regexp.Regexp
	reBlacklist   []*regexp.Regexp
	configuration Config
	metrics       map[string]uint
	metricsChan   = make(chan map[string]uint, 128)
	metricsWg     sync.WaitGroup
)

// Command line options
var (
	flDockerHost = flag.String("host", defaultDockerHost, "Docker daemon host")
	flCertPath   = flag.String("cert-path", "", "Path to Docker certificates (cert.pem, key.pem)")
	flTLSVerify  = flag.Bool("tls-verify", false, "Verify certificates")
	flDebug      = flag.Bool("debug", false, "Enable debug logging")
	flVersion    = flag.Bool("version", false, "Print version")
	flAddr       = flag.String("addr", defaultAddr, "Prometheus metrics socket [HOST:PORT]")
	flConfig     = flag.String("config", defaultConfig, "Path to plugin config file")
)

func readConfig(configFile string) error {
	file, err := os.Open(configFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// Decode JSON
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&configuration); err != nil {
		return err
	}

	// Build whitelist
	for _, v := range configuration.Whitelist {
		re, err := regexp.Compile(v)
		if err != nil {
			return err
		}
		reWhitelist = append(reWhitelist, re)
	}

	// Build blacklist
	for _, v := range configuration.Blacklist {
		re, err := regexp.Compile(v)
		if err != nil {
			return err
		}
		reBlacklist = append(reBlacklist, re)
	}

	return nil
}

func main() {
	logrus.SetLevel(logrus.InfoLevel)

	// Parse / handle arguments
	flag.Parse()
	if *flVersion {
		fmt.Printf("Version: %s\n", version)
		os.Exit(0)
	}
	if *flDebug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	logrus.Infof("Docker Image policy plugin started (version: %s)", version)

	// Read config
	if err := readConfig(*flConfig); err != nil {
		logrus.Fatal(err)
	}
	logrus.Infof("%d entries in whitelist.", len(reWhitelist))
	logrus.Infof("%d entries in blacklist.", len(reBlacklist))
	logrus.Infof("Default allow: %t", configuration.DefaultAllow)

	// Run metrics
	http.HandleFunc("/metrics", metricsHandler)
	go func() {
		logrus.Debugf("Metrics running on %s", *flAddr)
		if err := http.ListenAndServe(*flAddr, nil); err != nil {
			logrus.Fatal(err)
		}
	}()
	go metricsCounter()

	// Create Docker plugin
	plugin, err := newPlugin(*flDockerHost, *flCertPath, *flTLSVerify)
	if err != nil {
		logrus.Fatal(err)
	}

	// Socket for docker plugin
	h := authorization.NewHandler(plugin)
	logrus.Debugf("Plugin running on %s", pluginSocket)
	if err := h.ServeUnix(pluginSocket, 0); err != nil {
		logrus.Fatal(err)
	}
}

func metricsCounter() {
	// initialize
	metrics = make(map[string]uint)
	metrics["docker_image_policy{state=\"allow\"}"] = 0
	metrics["docker_image_policy{state=\"blacklist\"}"] = 0
	metrics["docker_image_policy{state=\"block\"}"] = 0
	metrics["docker_image_policy{state=\"query_err\"}"] = 0
	metrics["docker_image_policy{state=\"uri_err\"}"] = 0
	metrics["docker_image_policy{state=\"whitelist\"}"] = 0

	// update
	for metric := range metricsChan {
		metricsWg.Add(1)
		for key, value := range metric {
			metrics[key] += value
		}
		metricsWg.Done()
	}
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "# Prometheus metrics.")
	metricsWg.Wait()
	for key, value := range metrics {
		fmt.Fprintf(w, "%s %d\n", key, value)
	}
}
