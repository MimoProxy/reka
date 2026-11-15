//go:build ignore

package main

import (
	pb "github.com/metacubex/mihomo/component/geodata/router"
	"google.golang.org/protobuf/proto"
	"os"
)

func init() {
	writeProto := func(name string, m proto.Message) {
		b, e := proto.Marshal(m)
		if e != nil {
			panic(e)
		}
		if e = os.WriteFile(name, b, 0644); e != nil {
			panic(e)
		}
	}
	writeProto("geoip.dat", &pb.GeoIPList{Entry: []*pb.GeoIP{{CountryCode: "CN", Cidr: []*pb.CIDR{{Ip: []byte{192, 0, 2, 0}, Prefix: 24}, {Ip: []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Prefix: 32}}}, {CountryCode: "REVERSE", ReverseMatch: true, Cidr: []*pb.CIDR{{Ip: []byte{192, 0, 2, 0}, Prefix: 24}}}}})
	writeProto("geosite.dat", &pb.GeoSiteList{Entry: []*pb.GeoSite{{CountryCode: "TEST", Domain: []*pb.Domain{{Type: pb.Domain_Domain, Value: "suffix.test", Attribute: []*pb.Domain_Attribute{{Key: "cn", TypedValue: &pb.Domain_Attribute_BoolValue{BoolValue: true}}}}, {Type: pb.Domain_Full, Value: "exact.test"}, {Type: pb.Domain_Plain, Value: "keyword"}, {Type: pb.Domain_Regex, Value: `^regex[0-9]+\.test$`}}}}})
}
