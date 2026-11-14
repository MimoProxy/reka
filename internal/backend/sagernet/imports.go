// Package sagernet is the only package in Reka that imports sing-box and
// sing-tun. Everything else depends on interfaces defined by Reka.
//
// For now this file only pins the upstream packages the prototype needs, so
// the dependency graph matches what will actually be linked.
package sagernet

import (
	_ "github.com/sagernet/sing-box/adapter"
	_ "github.com/sagernet/sing-box/common/tls"
	_ "github.com/sagernet/sing-box/protocol/block"
	_ "github.com/sagernet/sing-box/protocol/direct"
	_ "github.com/sagernet/sing-box/protocol/http"
	_ "github.com/sagernet/sing-box/protocol/mixed"
	_ "github.com/sagernet/sing-box/protocol/shadowsocks"
	_ "github.com/sagernet/sing-box/protocol/socks"
	_ "github.com/sagernet/sing-box/protocol/vless"
	_ "github.com/sagernet/sing-tun"
)
