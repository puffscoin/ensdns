//go:generate abigen --sol contract/ens.sol --pkg contract --out contract/ens.go

package ens

import (
    "strings"

    "github.com/puffscoin/ensdns/ens/contract"
    "github.com/miekg/dns"
    "github.com/puffscoin/go-puffscoin/accounts/abi/bind"
    "github.com/puffscoin/go-puffscoin/common"
    "github.com/puffscoin/go-puffscoin/crypto"
)

func NameHash(name string) common.Hash {
    if name == "" {
        return common.Hash{}
    }

    parts := strings.SplitN(name, ".", 2)
    label := crypto.Keccak256Hash([]byte(parts[0]))
    parent := common.Hash{}
    if len(parts) > 1 {
        parent = NameHash(parts[1])
    }
    return crypto.Keccak256Hash(parent[:], label[:])
}

type Registry struct {
    backend bind.ContractBackend
    ens *contract.ENSSession
}

func New(backend bind.ContractBackend, registryAddress common.Address, opts bind.TransactOpts) (*Registry, error) {
    ens, err := contract.NewENS(registryAddress, backend)
    if err != nil {
        return nil, err
    }

    return &Registry{
        backend: backend,
        ens: &contract.ENSSession{
            Contract:     ens,
            TransactOpts: opts,
        },
    }, nil
}


func (reg *Registry) GetResolver(name string) (*Resolver, error) {
    node := NameHash(name)
    resolverAddr, err := reg.ens.Resolver(node)
    if err != nil {
        return nil, err
    }

    resolver, err := contract.NewResolver(resolverAddr, reg.backend)
    if err != nil {
        return nil, err
    }

    return &Resolver{
        Address: resolverAddr,
        node: node,
        registry: reg,
        resolver: &contract.ResolverSession{
            Contract:     resolver,
            TransactOpts: reg.ens.TransactOpts,
        },
    }, nil
}

type Resolver struct {
    Address common.Address
    node common.Hash
    registry *Registry
    resolver *contract.ResolverSession
}

func (res *Resolver) GetRRs() (rrs []dns.RR, err error) {
    rdata, err := res.resolver.Dnsrr(res.node)
    if err != nil {
        return nil, err
    }

    for off := 0; off < len(rdata); {
        r, off1, err := dns.UnpackRR(rdata, off)
        if err != nil {
            return nil, err
        }
        if off1 == off {
            break
        }
        off = off1
        rrs = append(rrs, r)
    }
    return rrs, nil
}

func packRRs(rrs []dns.RR) (rdata []byte, err error) {
    len := (&dns.Msg{Answer: rrs}).Len()

    rdata = make([]byte, len)
    off := 0
    compression := make(map[string]int)
    for _, rr := range rrs {
        off, err = dns.PackRR(rr, rdata, off, compression, true)
        if err != nil {
            return nil, err
        }
    }

    return rdata[:off], nil
}

func (res *Resolver) SetRRs(rrs []dns.RR) error {
    rdata, err := packRRs(rrs)
    if err != nil {
        return err
    }

    _, err = res.resolver.SetDnsrr(res.node, rdata)
    return err
}

func (res *Resolver) GetTTL() (uint64, error) {
    return res.registry.ens.Ttl(res.node)
}
