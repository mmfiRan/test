package mdnsscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const mdnsPort = 5353

var (
	ipv4Group = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: mdnsPort}
	ipv6Group = &net.UDPAddr{IP: net.ParseIP("ff02::fb"), Port: mdnsPort}
)

type Asset struct {
	Service string
	Proto   string
	Port    int

	InstanceName string
	Hostname     string
	TTL          uint32

	IPv4 []netip.Addr
	IPv6 []netip.Addr

	TXT map[string]string
}

type Result struct {
	Assets       []Asset
	ServiceTypes []string
}

type Scanner struct {
	Timeout      time.Duration
	ServiceHints []string // optional fallback types, e.g. _http._tcp.local.
}

func NewScanner() *Scanner {
	return &Scanner{
		Timeout: 5 * time.Second,
		ServiceHints: []string{
			"_workstation._tcp.local.",
			"_http._tcp.local.",
			"_smb._tcp.local.",
			"_qdiscover._tcp.local.",
			"_device-info._tcp.local.",
			"_afpovertcp._tcp.local.",
		},
	}
}

func (s *Scanner) Scan(ctx context.Context) (Result, error) {
	if s.Timeout <= 0 {
		return Result{}, fmt.Errorf("timeout must be > 0")
	}

	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	listeners, err := openListeners()
	if err != nil {
		return Result{}, err
	}
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()

	sender4, sender6, err := openSenders()
	if err != nil {
		return Result{}, err
	}
	defer func() {
		if sender4 != nil {
			_ = sender4.Close()
		}
		if sender6 != nil {
			_ = sender6.Close()
		}
	}()

	cache := newCache()

	var wg sync.WaitGroup
	wg.Add(len(listeners))
	for _, l := range listeners {
		go func(c *net.UDPConn) {
			defer wg.Done()
			readLoop(ctx, c, cache)
		}(l)
	}

	// 1) Enumerate service types.
	_ = sendQuery(sender4, sender6, "_services._dns-sd._udp.local.", dns.TypePTR)

	// 2) Query each discovered type (or fallback types) for instances.
	sleepOrDone(ctx, 350*time.Millisecond)
	types := cache.serviceTypes()
	if len(types) == 0 {
		types = append([]string(nil), s.ServiceHints...)
	}
	for _, t := range types {
		_ = sendQuery(sender4, sender6, dns.Fqdn(t), dns.TypePTR)
	}

	// 3) Repeatedly query instances/targets during the scan window.
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return cache.result(), nil
		default:
		}

		for _, inst := range cache.instances() {
			_ = sendQuery(sender4, sender6, inst, dns.TypeSRV)
			_ = sendQuery(sender4, sender6, inst, dns.TypeTXT)
		}
		for _, host := range cache.targets() {
			_ = sendQuery(sender4, sender6, host, dns.TypeA)
			_ = sendQuery(sender4, sender6, host, dns.TypeAAAA)
		}

		sleepOrDone(ctx, 500*time.Millisecond)
	}
}

type cache struct {
	mu sync.Mutex

	serviceTypeSet map[string]struct{}
	ptrByType      map[string]map[string]uint32 // serviceType -> instance -> ttl
	srvByInstance  map[string]srvRec
	txtByInstance  map[string]map[string]string

	ipv4ByHost map[string]map[netip.Addr]uint32 // hostname -> ip -> ttl
	ipv6ByHost map[string]map[netip.Addr]uint32
}

type srvRec struct {
	target string
	port   uint16
	ttl    uint32
}

func newCache() *cache {
	return &cache{
		serviceTypeSet: map[string]struct{}{},
		ptrByType:      map[string]map[string]uint32{},
		srvByInstance:  map[string]srvRec{},
		txtByInstance:  map[string]map[string]string{},
		ipv4ByHost:     map[string]map[netip.Addr]uint32{},
		ipv6ByHost:     map[string]map[netip.Addr]uint32{},
	}
}

func (c *cache) addRR(rr dns.RR) {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch v := rr.(type) {
	case *dns.PTR:
		name := dns.Fqdn(v.Hdr.Name)
		ptr := dns.Fqdn(v.Ptr)
		if name == "_services._dns-sd._udp.local." {
			c.serviceTypeSet[ptr] = struct{}{}
			return
		}
		if _, ok := c.ptrByType[name]; !ok {
			c.ptrByType[name] = map[string]uint32{}
		}
		c.ptrByType[name][ptr] = v.Hdr.Ttl
	case *dns.SRV:
		inst := dns.Fqdn(v.Hdr.Name)
		c.srvByInstance[inst] = srvRec{
			target: dns.Fqdn(v.Target),
			port:   v.Port,
			ttl:    v.Hdr.Ttl,
		}
	case *dns.TXT:
		inst := dns.Fqdn(v.Hdr.Name)
		if _, ok := c.txtByInstance[inst]; !ok {
			c.txtByInstance[inst] = map[string]string{}
		}
		for _, t := range v.Txt {
			k, val, ok := strings.Cut(t, "=")
			if ok {
				c.txtByInstance[inst][k] = val
				continue
			}
			c.txtByInstance[inst][t] = ""
		}
	case *dns.A:
		host := dns.Fqdn(v.Hdr.Name)
		addr, ok := netip.AddrFromSlice(v.A.To4())
		if !ok {
			return
		}
		if _, ok := c.ipv4ByHost[host]; !ok {
			c.ipv4ByHost[host] = map[netip.Addr]uint32{}
		}
		c.ipv4ByHost[host][addr] = v.Hdr.Ttl
	case *dns.AAAA:
		host := dns.Fqdn(v.Hdr.Name)
		addr, ok := netip.AddrFromSlice(v.AAAA)
		if !ok {
			return
		}
		if _, ok := c.ipv6ByHost[host]; !ok {
			c.ipv6ByHost[host] = map[netip.Addr]uint32{}
		}
		c.ipv6ByHost[host][addr] = v.Hdr.Ttl
	default:
	}
}

func (c *cache) serviceTypes() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.serviceTypeSet))
	for t := range c.serviceTypeSet {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func (c *cache) instances() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	set := map[string]struct{}{}
	for _, m := range c.ptrByType {
		for inst := range m {
			set[inst] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for inst := range set {
		out = append(out, inst)
	}
	sort.Strings(out)
	return out
}

func (c *cache) targets() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	set := map[string]struct{}{}
	for _, srv := range c.srvByInstance {
		if srv.target != "" {
			set[srv.target] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for host := range set {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func (c *cache) result() Result {
	c.mu.Lock()
	defer c.mu.Unlock()

	var assets []Asset
	for serviceType, instances := range c.ptrByType {
		service, proto := parseServiceType(serviceType)
		for inst, ptrTTL := range instances {
			srv, ok := c.srvByInstance[inst]
			if !ok {
				continue
			}
			host := srv.target

			var v4 []netip.Addr
			for ip := range c.ipv4ByHost[host] {
				v4 = append(v4, ip)
			}
			sort.Slice(v4, func(i, j int) bool { return v4[i].Less(v4[j]) })

			var v6 []netip.Addr
			for ip := range c.ipv6ByHost[host] {
				v6 = append(v6, ip)
			}
			sort.Slice(v6, func(i, j int) bool { return v6[i].Less(v6[j]) })

			txt := map[string]string(nil)
			if m, ok := c.txtByInstance[inst]; ok {
				txt = make(map[string]string, len(m))
				for k, v := range m {
					txt[k] = v
				}
			}

			ttl := srv.ttl
			if ttl == 0 {
				ttl = ptrTTL
			}

			assets = append(assets, Asset{
				Service:      service,
				Proto:        proto,
				Port:         int(srv.port),
				InstanceName: instanceBase(inst),
				Hostname:     strings.TrimSuffix(host, "."),
				TTL:          ttl,
				IPv4:         v4,
				IPv6:         v6,
				TXT:          txt,
			})
		}
	}

	sort.Slice(assets, func(i, j int) bool {
		if assets[i].Port != assets[j].Port {
			return assets[i].Port < assets[j].Port
		}
		if assets[i].Proto != assets[j].Proto {
			return assets[i].Proto < assets[j].Proto
		}
		if assets[i].Service != assets[j].Service {
			return assets[i].Service < assets[j].Service
		}
		return assets[i].Hostname < assets[j].Hostname
	})

	types := make([]string, 0, len(c.serviceTypeSet))
	for t := range c.serviceTypeSet {
		types = append(types, strings.TrimSuffix(t, "."))
	}
	sort.Strings(types)

	return Result{Assets: assets, ServiceTypes: types}
}

func instanceBase(instanceFQDN string) string {
	instanceFQDN = strings.TrimSuffix(instanceFQDN, ".")
	parts := strings.Split(instanceFQDN, "._")
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	labels := strings.Split(instanceFQDN, ".")
	if len(labels) > 0 {
		return labels[0]
	}
	return instanceFQDN
}

func parseServiceType(serviceTypeFQDN string) (service, proto string) {
	serviceTypeFQDN = strings.TrimSuffix(strings.ToLower(serviceTypeFQDN), ".")
	labels := strings.Split(serviceTypeFQDN, ".")
	if len(labels) < 2 {
		return strings.TrimPrefix(serviceTypeFQDN, "_"), ""
	}
	service = strings.TrimPrefix(labels[0], "_")
	proto = strings.TrimPrefix(labels[1], "_")
	return service, proto
}

func openListeners() ([]*net.UDPConn, error) {
	var conns []*net.UDPConn

	ifaces, _ := net.Interfaces()
	for _, ifi := range ifaces {
		if (ifi.Flags&net.FlagUp) == 0 || (ifi.Flags&net.FlagMulticast) == 0 {
			continue
		}

		c4, err := net.ListenMulticastUDP("udp4", &ifi, ipv4Group)
		if err == nil {
			_ = c4.SetReadBuffer(1 << 20)
			conns = append(conns, c4)
		}

		c6, err := net.ListenMulticastUDP("udp6", &ifi, ipv6Group)
		if err == nil {
			_ = c6.SetReadBuffer(1 << 20)
			conns = append(conns, c6)
		}
	}

	if len(conns) == 0 {
		if c4, err := net.ListenMulticastUDP("udp4", nil, ipv4Group); err == nil {
			_ = c4.SetReadBuffer(1 << 20)
			conns = append(conns, c4)
		}
		if c6, err := net.ListenMulticastUDP("udp6", nil, ipv6Group); err == nil {
			_ = c6.SetReadBuffer(1 << 20)
			conns = append(conns, c6)
		}
	}

	if len(conns) == 0 {
		return nil, errors.New("failed to open mDNS multicast listener (no multicast-capable interfaces?)")
	}
	return conns, nil
}

func openSenders() (sender4, sender6 *net.UDPConn, err error) {
	sender4, _ = net.DialUDP("udp4", nil, ipv4Group)
	sender6, _ = net.DialUDP("udp6", nil, ipv6Group)
	if sender4 == nil && sender6 == nil {
		return nil, nil, errors.New("failed to open mDNS sender sockets")
	}
	return sender4, sender6, nil
}

func readLoop(ctx context.Context, conn *net.UDPConn, cache *cache) {
	buf := make([]byte, 64<<10)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			var ne *net.OpError
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}

		var msg dns.Msg
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}

		for _, rr := range msg.Answer {
			cache.addRR(rr)
		}
		for _, rr := range msg.Extra {
			cache.addRR(rr)
		}
		for _, rr := range msg.Ns {
			cache.addRR(rr)
		}
	}
}

func sendQuery(sender4, sender6 *net.UDPConn, name string, qtype uint16) error {
	m := new(dns.Msg)
	m.Id = 0
	m.RecursionDesired = false
	m.Question = []dns.Question{{
		Name:   dns.Fqdn(name),
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}}
	packed, err := m.Pack()
	if err != nil {
		return err
	}

	var firstErr error
	if sender4 != nil {
		if _, err := sender4.Write(packed); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if sender6 != nil {
		if _, err := sender6.Write(packed); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func sleepOrDone(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
