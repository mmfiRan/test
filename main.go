package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"mdnsscan/internal/mdnsscan"
	"mdnsscan/internal/ports"
)

func main() {
	var (
		cidr    = flag.String("cidr", "", "CIDR to filter discovered IPs, e.g. 192.168.1.0/24")
		portsIn = flag.String("ports", "1-65535", "Port set to include, e.g. 80,443,5000-6000")
		timeout = flag.Duration("timeout", 5*time.Second, "How long to listen for mDNS responses")
	)
	flag.Parse()

	if *cidr == "" {
		fmt.Fprintln(os.Stderr, "missing required flag: -cidr")
		os.Exit(2)
	}

	_, ipnet, err := net.ParseCIDR(*cidr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -cidr: %v\n", err)
		os.Exit(2)
	}

	portSet, err := ports.Parse(*portsIn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -ports: %v\n", err)
		os.Exit(2)
	}

	scanner := mdnsscan.NewScanner()
	scanner.Timeout = *timeout

	res, err := scanner.Scan(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		os.Exit(1)
	}

	filtered := make([]mdnsscan.Asset, 0, len(res.Assets))
	for _, a := range res.Assets {
		if !portSet.Contains(a.Port) {
			continue
		}
		if !assetInCIDR(a, ipnet) {
			continue
		}
		filtered = append(filtered, a)
	}

	fmt.Println("services:")
	for _, a := range filtered {
		fmt.Printf("%d/%s %s:\n", a.Port, a.Proto, a.Service)
		fmt.Printf("Name=%s\n", a.InstanceName)
		if len(a.IPv4) > 0 {
			fmt.Printf("IPv4=%s\n", a.IPv4[0].String())
		}
		if len(a.IPv6) > 0 {
			fmt.Printf("IPv6=%s\n", a.IPv6[0].String())
		}
		if a.Hostname != "" {
			fmt.Printf("Hostname=%s\n", a.Hostname)
		}
		if a.TTL != 0 {
			fmt.Printf("TTL=%d\n", a.TTL)
		}
		if banner := formatBanner(a.TXT); banner != "" {
			fmt.Println(banner)
		}
	}

	if len(res.ServiceTypes) > 0 {
		fmt.Println("answers:")
		fmt.Println("PTR:")
		for _, t := range res.ServiceTypes {
			fmt.Println(t)
		}
	}
}

func assetInCIDR(a mdnsscan.Asset, ipnet *net.IPNet) bool {
	for _, ip := range a.IPv4 {
		if ipnet.Contains(net.IP(ip.AsSlice())) {
			return true
		}
	}
	for _, ip := range a.IPv6 {
		if ipnet.Contains(net.IP(ip.AsSlice())) {
			return true
		}
	}
	return false
}

func formatBanner(txt map[string]string) string {
	if len(txt) == 0 {
		return ""
	}
	keys := make([]string, 0, len(txt))
	for k := range txt {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if v := txt[k]; v == "" {
			parts = append(parts, k)
		} else {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, ",")
}
