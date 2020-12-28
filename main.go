package main

import (
	"fmt"
	"strings"
	"log"
	"flag"
	"bufio"
	"time"
	"path/filepath"
	"math"
	"os"
	"sync"
	"github.com/likexian/whois-go"
	"github.com/likexian/whois-parser-go"
)

var (
	defaultInterval, _ = time.ParseDuration("12h")
	// CLI flags
	flagDomainFile = flag.String("domain-file", "", "Path to file with domains (separated by newlines)")
	flagInterval   = flag.Duration("interval", defaultInterval, "Interval to check domains at")
	
	defaultDateFormats = []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02 (YYYY-MM-DD)",
		time.RFC3339,
	}

	nFlag = flag.Int("n", 1234, "help message for flag n")
	flagvar int
)

func init() {
	flag.IntVar(&flagvar, "flagname", 1234, "help message for flagname")
}


func main() {
	
	flag.Parse()

	// read and verify config file
	if *flagDomainFile == "" {
		log.Fatalf("no -domain-file specified")
	}

	//data, err := whois.Whois("likexian.com")
	//result, err := whoisparser.Parse(data)
	//fmt.Println(result.Domain.ExpirationDate)

	domains, err := readDomainFile(*flagDomainFile)
	if err != nil {
		log.Fatalf("error getting domains %q: %v", *flagDomainFile, err)
	}
	
	//for i := range domains {
	//	log.Printf("INFO monitoring %s", domains[i])
	//}
	// Setup internal checker
	check := &checker{
		domains:  domains,
		interval: *flagInterval,
	}
	//fmt.Println(check.getExpiration("lonlife.cn"))
	var wg sync.WaitGroup
	wg.Add(32)
	go check.checkAll()
	wg.Wait()
	//check.checkAll()
}

type checker struct {
	domains []string
	t *time.Ticker
	interval time.Duration
}

func (c *checker) checkAll() {
	if c.t == nil {
		c.t = time.NewTicker(c.interval)
		c.checkNow() // check domains right away after ticker setup
	}
	for range c.t.C {
		c.checkNow()
	}
}

func (c *checker) checkNow() {
	for i := range c.domains {
		expr, err := c.getExpiration(c.domains[i])
		if err != nil {
			log.Printf("error getting WhoisServer expiration for %s: %v", c.domains[i], err)
		}
		days := math.Floor(time.Until(*expr).Hours() / 24)
		//		c.handler.WithLabelValues(c.domains[i]).Set(days)
		log.Printf("%s expires in %.2f days", c.domains[i], days)
	}
}

func (c *checker) getExpiration(d string) (*time.Time, error) {
	data, err := whois.Whois(d)
	if err != nil {
		log.Println(err)
	}
	//whoisraw := strings.TrimSpace(data)
	result, err := whoisparser.Parse(data)
	//log.Printf(whoisraw)
	if err == nil {
		// Print the domain status
		//fmt.Printf("%s\t%s\t%s\n", result.Domain.Status , result.Domain.Domain , result.Domain.ExpirationDate)

		for j := range defaultDateFormats {
			when, err := time.Parse(defaultDateFormats[j], result.Domain.ExpirationDate)			
			if err != nil {
				continue
			}
			return &when, nil
		}
		return nil, fmt.Errorf("unable to find parsable format for %q", result.Domain.ExpirationDate)
	}
	return nil, err
}


func readDomainFile(where string) ([]string, error) {
	fullPath, err := filepath.Abs(where)
	if err != nil {
		return nil, fmt.Errorf("when expanding %s: %v", *flagDomainFile, err)
	}

	fd, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("when opening %s: %v", fullPath, err)
	}
	defer fd.Close()
	r := bufio.NewScanner(fd)

	var domains []string
	for r.Scan() {
		domains = append(domains, strings.TrimSpace(r.Text()))
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains found in %s", fullPath)
	}
	return domains, nil
}
