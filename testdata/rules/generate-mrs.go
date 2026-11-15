//go:build ignore

package main

import (
	"bytes"
	"encoding/binary"
	"github.com/klauspost/compress/zstd"
	"github.com/metacubex/mihomo/component/cidr"
	"github.com/metacubex/mihomo/component/trie"
	"os"
)

func write(name string, kind byte, count int64, body func(*bytes.Buffer) error) {
	var b bytes.Buffer
	b.Write([]byte{'M', 'R', 'S', 1, kind})
	binary.Write(&b, binary.BigEndian, count)
	binary.Write(&b, binary.BigEndian, int64(0))
	if e := body(&b); e != nil {
		panic(e)
	}
	z, _ := zstd.NewWriter(nil)
	defer z.Close()
	if e := os.WriteFile(name, z.EncodeAll(b.Bytes(), nil), 0644); e != nil {
		panic(e)
	}
}
func main() {
	var b trie.DomainSetBuilder
	for _, v := range []string{"exact.test", "+.suffix.test", ".sub.test", "*.one.test", "a.*.nested.test"} {
		if e := b.Insert(v); e != nil {
			panic(e)
		}
	}
	set := b.Build()
	write("domain.mrs", 0, 5, func(b *bytes.Buffer) error { return set.WriteBin(b) })
	ips := cidr.NewIpCidrSet()
	for _, v := range []string{"192.0.2.0/24", "2001:db8::/32"} {
		ips.AddIpCidrForString(v)
	}
	ips.Merge()
	write("ipcidr.mrs", 1, 2, func(b *bytes.Buffer) error { return ips.WriteBin(b) })
}
