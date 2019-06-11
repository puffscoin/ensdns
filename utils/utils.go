package utils

import (
    "errors"
    "fmt"
    "net"
    "strings"

    "github.com/miekg/dns"
)

var TimeoutError = errors.New("All DNS servers timed out")

func FindNS(client *dns.Client, servers []string, name, nssuffix string) (*dns.NS, error) {
    query := dns.Msg{}
    query.SetQuestion(name, dns.TypeNS)
    query.RecursionDesired = false

    for _, server := range servers {
        r, _, err := client.Exchange(&query, server+":53")
        if err, ok := err.(net.Error); ok && err.Timeout() {
            continue
        }
        if err != nil {
            return nil, err
        }
        if r == nil || r.Rcode != dns.RcodeSuccess {
            return nil, fmt.Errorf("Got nil or error response from NS query: %v", r)
        }

        subservers := make([]string, 0)
        for _, rec := range r.Ns {
            switch rec := rec.(type) {
            case *dns.NS:
                if strings.HasSuffix(rec.Ns, nssuffix) {
                    return rec, nil
                }
                subservers = append(subservers, rec.Ns)
            }
        }
        if len(subservers) > 0 {
            return FindNS(client, subservers, name, nssuffix)
        }
    }
    return nil, TimeoutError
}
