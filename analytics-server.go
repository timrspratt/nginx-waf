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
    Limit           int
	Minutes         int
	StatusCode      []string
	Country         []string
	Continent       []string
	Path            []string
	UserAgent       []string
	ASN             []string
	IP              []string
}

type AggregatedData struct {
    PeriodStart                 string  `json:"period_start"`
	PeriodEnd                   string  `json:"period_end"`
	TotalRequests               int  `json:"total_requests"`
	RequestsPerMinute           []Entry `json:"requests_per_minute"`
	RequestsPerCountry          []Entry `json:"requests_per_country"`
	RequestsPerContinent        []Entry `json:"requests_per_continent"`
	RequestsPerUserAgent        []Entry `json:"requests_per_user_agent"`
	RequestsPerPath             []Entry `json:"requests_per_path"`
	RequestsPerStatusCode       []Entry `json:"requests_per_status_code"`
	RequestsPerASNOrg           []Entry `json:"requests_per_asn_org"`
	RequestsPerIP               []Entry `json:"requests_per_ip"`
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

func aggregateHandler(w http.ResponseWriter, r *http.Request) {
	logFilePaths := r.URL.Query().Get("file")
	if logFilePaths == "" {
		http.Error(w, "Missing 'file' query parameter", http.StatusBadRequest)
		return
	}

    files := strings.Split(logFilePaths, ",")

    includeParam := r.URL.Query().Get("include")
    include := strings.Split(includeParam, ",")

	filters := parseFilters(r)

	currentTime := time.Now().UTC()
	cutoffTime := currentTime.Add(-time.Duration(filters.Minutes) * time.Minute)

	const timeFormat = "2006-01-02T15:04"
    periodEnd := currentTime.Format(timeFormat)
    periodStart := cutoffTime.Format(timeFormat)

	countPerMinute := make(map[string]int)
	countPerCountry := make(map[string]int)
	countPerContinent := make(map[string]int)
	countPerUserAgent := make(map[string]int)
	countPerStatusCode := make(map[string]int)
	countPerPath := make(map[string]int)
	countPerASNOrg := make(map[string]int)
	countPerIP := make(map[string]int)
	totalRequests := 0
	cutoffReached := false

	for _, logFilePath := range files {
        err := processLogFile(
            logFilePath, cutoffTime, timeFormat, filters, countPerMinute,
            countPerCountry, countPerContinent, countPerUserAgent, countPerStatusCode,
            countPerPath, countPerASNOrg, countPerIP,
            &totalRequests, &cutoffReached,
        )
        if err != nil {
            http.Error(w, fmt.Sprintf("Error processing log file %s: %v", logFilePath, err), http.StatusInternalServerError)
            return
        }

        if cutoffReached {
            break
        }
    }

    result := AggregatedData {
		PeriodStart:   periodStart,
		PeriodEnd:     periodEnd,
		TotalRequests: totalRequests,
	}

    if includeParam == "" || include[0] == "" {
		include = []string {
            "requests_per_minute",
            "requests_per_country",
            "requests_per_continent",
            "requests_per_user_agent",
            "requests_per_status_code",
            "requests_per_path",
            "requests_per_asn_org",
            "requests_per_ip",
        }
	}

	if contains(include, "requests_per_minute") || len(include) == 0 {
		result.RequestsPerMinute = getTopN(countPerMinute, 0)
	}
	if contains(include, "requests_per_country") || len(include) == 0 {
		result.RequestsPerCountry = getTopN(countPerCountry, filters.Limit)
	}
    if contains(include, "requests_per_continent") || len(include) == 0 {
		result.RequestsPerContinent = getTopN(countPerContinent, filters.Limit)
	}
	if contains(include, "requests_per_user_agent") || len(include) == 0 {
		result.RequestsPerUserAgent = getTopN(countPerUserAgent, filters.Limit)
	}
    if contains(include, "requests_per_status_code") || len(include) == 0 {
		result.RequestsPerStatusCode = getTopN(countPerStatusCode, filters.Limit)
	}
	if contains(include, "requests_per_path") || len(include) == 0 {
		result.RequestsPerPath = getTopN(countPerPath, filters.Limit)
	}
	if contains(include, "requests_per_asn_org") || len(include) == 0 {
		result.RequestsPerASNOrg = getTopN(countPerASNOrg, filters.Limit)
	}
	if contains(include, "requests_per_ip") || len(include) == 0 {
		result.RequestsPerIP = getTopN(countPerIP, filters.Limit)
	}

	w.Header().Set("Content-Type", "application/json")
	jsonOutput, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error generating JSON output: %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(jsonOutput)
}

func processLogFile(
    logFilePath string,
    cutoffTime time.Time,
    timeFormat string,
    filters Filters,
    countPerMinute map[string]int,
    countPerCountry map[string]int,
    countPerContinent map[string]int,
    countPerUserAgent map[string]int,
    countPerStatusCode map[string]int,
    countPerPath map[string]int,
    countPerASNOrg map[string]int,
    countPerIP map[string]int,
    totalRequests *int,
    cutoffReached *bool,
) error {
    file, err := os.Open(logFilePath)
	if err != nil {
		return nil
	}
	defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()
        fields := strings.Split(line, "\t")

        if len(fields) < 10 {
            continue
        }

        timestampStr := strings.ReplaceAll(strings.ReplaceAll(fields[0], "]", ""), "[", "")
        timestamp, err := time.Parse(time.RFC3339, timestampStr)
        if err != nil {
            continue
        }

        utcStamp := timestamp.UTC()

        if utcStamp.Before(cutoffTime) {
            (*cutoffReached) = true
            continue
         }

        ip := fields[1]
        asn := fields[2]
        asnOrg := asn + " - " + fields[3]
        country := fields[4]
        continent := fields[5]
        statusCode := fields[6]
        path := fields[8]
        userAgent := fields[9]

        if !matchesFilter(statusCode, filters.StatusCode) ||
            !matchesFilter(country, filters.Country) ||
            !matchesFilter(continent, filters.Continent) ||
            !matchesFilter(path, filters.Path) ||
            !matchesFilter(userAgent, filters.UserAgent) ||
            !matchesFilter(asn, filters.ASN) ||
            !matchesFilter(ip, filters.IP) {
            continue
        }

        minute := utcStamp.Format(timeFormat)
        countPerMinute[minute]++
        countPerCountry[country]++
        countPerContinent[continent]++
        countPerUserAgent[userAgent]++
        countPerStatusCode[statusCode]++
        countPerPath[path]++
        countPerASNOrg[asnOrg]++
        countPerIP[ip]++
        (*totalRequests)++
    }

	return nil
}

func parseFilters(r *http.Request) Filters {
	filters := Filters {
	    Limit:          10,
		Minutes:        10,
		StatusCode:     strings.Split(r.URL.Query().Get("status-code"), ","),
		Country:        strings.Split(r.URL.Query().Get("country"), ","),
		Continent:      strings.Split(r.URL.Query().Get("continent"), ","),
		Path:           strings.Split(r.URL.Query().Get("path"), ","),
		UserAgent:      strings.Split(r.URL.Query().Get("user-agent"), ","),
		ASN:            strings.Split(r.URL.Query().Get("asn"), ","),
		IP:             strings.Split(r.URL.Query().Get("ip"), ","),
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

func getTopN(countMap map[string]int, n int) []Entry {
	entries := make([]Entry, 0, len(countMap))
	for key, count := range countMap {
		entries = append(entries, Entry{Key: key, Count: count})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})

	if n > 0 && len(entries) > n {
		return entries[:n]
	}
	return entries
}

func contains(slice []string, item string) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}