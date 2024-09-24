package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"flag"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Filters struct {
    Limit       int
	Minutes     int
	StatusCode  []string
	Country     []string
	Path        []string
	UserAgent   []string
	ASN         []string
	IP          []string
}

type AggregatedData struct {
	RequestsPerMinute       []Entry `json:"requests_per_minute"`
	RequestsPerCountry      []Entry `json:"requests_per_country"`
	RequestsPerUserAgent    []Entry `json:"requests_per_user_agent"`
	RequestsPerPath         []Entry `json:"requests_per_path"`
	RequestsPerStatusCode   []Entry `json:"requests_per_status_code"`
	RequestsPerASNOrg       []Entry `json:"requests_per_asn_org"`
	RequestsPerIP           []Entry `json:"requests_per_ip"`
}

type Entry struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

var serverPort string

func main() {
	flag.StringVar(&serverPort, "port", "8080", "Port to run the web server on")
	flag.Parse()

	http.HandleFunc("/", aggregateHandler)
	fmt.Printf("Starting server on :%s\n", serverPort)
	err := http.ListenAndServe("127.0.0.1:"+serverPort, nil)
	if err != nil {
		fmt.Printf("Error starting server: %v\n", err)
	}
}

// Handler function for the root ("/") endpoint
func aggregateHandler(w http.ResponseWriter, r *http.Request) {
	// Get the file path from the query string
	logFilePath := r.URL.Query().Get("file")
	if logFilePath == "" {
		http.Error(w, "Missing 'file' query parameter", http.StatusBadRequest)
		return
	}

	// Parse query parameters for filters
	filters := parseFilters(r)

	// Open the log file
	file, err := os.Open(logFilePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error opening log file: %v", err), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Get the current time and calculate the cutoff time
	currentTime := time.Now().UTC()
	cutoffTime := currentTime.Add(-time.Duration(filters.Minutes) * time.Minute)

	// Maps for counting
	countPerMinute := make(map[string]int)
	countPerCountry := make(map[string]int)
	countPerUserAgent := make(map[string]int)
	countPerStatusCode := make(map[string]int)
	countPerPath := make(map[string]int)
	countPerASNOrg := make(map[string]int)
	countPerIP := make(map[string]int)

	// Read and process the log file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, "\t")

		// Ensure there are enough fields in the log entry
		if len(fields) < 9 {
			continue
		}

		// Parse the timestamp
		timestampStr := fields[0][1:20]
		timestamp, err := time.Parse(time.RFC3339, timestampStr+"Z")
		if err != nil || timestamp.Before(cutoffTime) {
			continue
		}

		// Extract relevant fields
		ip := fields[1]
		asn := fields[2]
		asnOrg := asn + " " + fields[3]
		country := fields[4]
		statusCode := fields[5]
		path := fields[7]
		userAgent := fields[8]

		// Apply filters
		if !matchesFilter(statusCode, filters.StatusCode) ||
			!matchesFilter(country, filters.Country) ||
			!matchesFilter(path, filters.Path) ||
			!matchesFilter(userAgent, filters.UserAgent) ||
			!matchesFilter(asn, filters.ASN) ||
			!matchesFilter(ip, filters.IP) {
			continue
		}

		// Aggregate counts
		minute := timestamp.Format("2006-01-02T15:04")
		countPerMinute[minute]++
		countPerCountry[country]++
		countPerUserAgent[userAgent]++
		countPerStatusCode[statusCode]++
		countPerPath[path]++
		countPerASNOrg[asnOrg]++
		countPerIP[ip]++
	}

	// Prepare the result
	result := AggregatedData{
		RequestsPerMinute:      getTopN(countPerMinute, 0),
		RequestsPerCountry:     getTopN(countPerCountry, filters.Limit),
		RequestsPerUserAgent:   getTopN(countPerUserAgent, filters.Limit),
		RequestsPerStatusCode:  getTopN(countPerStatusCode, filters.Limit),
		RequestsPerPath:        getTopN(countPerPath, filters.Limit),
		RequestsPerASNOrg:      getTopN(countPerASNOrg, filters.Limit),
		RequestsPerIP:          getTopN(countPerIP, filters.Limit),
	}

	// Output as JSON
	w.Header().Set("Content-Type", "application/json")
	jsonOutput, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error generating JSON output: %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(jsonOutput)
}

// Parse query parameters into filters
func parseFilters(r *http.Request) Filters {
	filters := Filters {
	    Limit:      10,
		Minutes:    10,
		StatusCode: strings.Split(r.URL.Query().Get("status-code"), ","),
		Country:    strings.Split(r.URL.Query().Get("country"), ","),
		Path:       strings.Split(r.URL.Query().Get("path"), ","),
		UserAgent:  strings.Split(r.URL.Query().Get("user-agent"), ","),
		ASN:        strings.Split(r.URL.Query().Get("asn"), ","),
		IP:         strings.Split(r.URL.Query().Get("ip"), ","),
	}

	if minutesStr := r.URL.Query().Get("minutes"); minutesStr != "" {
		minutes, err := strconv.Atoi(minutesStr)
		if err == nil {
			filters.Minutes = minutes
		}
	}
    if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err == nil {
			filters.Limit = limit
		}
	}
	return filters
}

// Check if a value matches any in the filter
func matchesFilter(value string, filter []string) bool {
	if len(filter) == 1 && filter[0] == "" {
		return true
	}
	for _, f := range filter {
		if f == value {
			return true
		}
	}
	return false
}

// Get top N entries sorted by count
func getTopN(countMap map[string]int, n int) []Entry {
	entries := make([]Entry, 0, len(countMap))
	for key, count := range countMap {
		entries = append(entries, Entry{Key: key, Count: count})
	}

	// Sort by count in descending order
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})

	// Return top N entries
	if n > 0 && len(entries) > n {
		return entries[:n]
	}
	return entries
}