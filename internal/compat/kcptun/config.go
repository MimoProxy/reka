// Config defaults and block ciphers follow MetaCubeX/mihomo v1.19.34.
// GPL-3.0-or-later; see ORIGIN.md and repository LICENSE.
package kcptun

import (
	"crypto/sha1"

	"fmt"
	"math"

	"github.com/metacubex/kcp-go"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// SALT is use for pbkdf2 key expansion
	SALT = "kcp-go"
	// maximum supported smux version
	maxSmuxVer = 2
	// scavenger check period
	scavengePeriod = 5
)

type Config struct {
	Key          string `json:"key" yaml:"key"`
	Crypt        string `json:"crypt" yaml:"crypt"`
	Mode         string `json:"mode" yaml:"mode"`
	Conn         int    `json:"conn" yaml:"conn"`
	AutoExpire   int    `json:"autoexpire" yaml:"autoexpire"`
	ScavengeTTL  int    `json:"scavengettl" yaml:"scavengettl"`
	MTU          int    `json:"mtu" yaml:"mtu"`
	RateLimit    int    `json:"ratelimit" yaml:"ratelimit"`
	SndWnd       int    `json:"sndwnd" yaml:"sndwnd"`
	RcvWnd       int    `json:"rcvwnd" yaml:"rcvwnd"`
	DataShard    int    `json:"datashard" yaml:"datashard"`
	ParityShard  int    `json:"parityshard" yaml:"parityshard"`
	DSCP         int    `json:"dscp" yaml:"dscp"`
	NoComp       bool   `json:"nocomp" yaml:"nocomp"`
	AckNodelay   bool   `json:"acknodelay" yaml:"acknodelay"`
	NoDelay      int    `json:"nodelay" yaml:"nodelay"`
	Interval     int    `json:"interval" yaml:"interval"`
	Resend       int    `json:"resend" yaml:"resend"`
	NoCongestion int    `json:"nc" yaml:"nc"`
	SockBuf      int    `json:"sockbuf" yaml:"sockbuf"`
	SmuxVer      int    `json:"smuxver" yaml:"smuxver"`
	SmuxBuf      int    `json:"smuxbuf" yaml:"smuxbuf"`
	FrameSize    int    `json:"framesize" yaml:"framesize"`
	StreamBuf    int    `json:"streambuf" yaml:"streambuf"`
	KeepAlive    int    `json:"keepalive" yaml:"keepalive"`
}

func (config *Config) FillDefaults() {
	if config.Key == "" {
		config.Key = "it's a secrect"
	}
	if config.Crypt == "" {
		config.Crypt = "aes"
	}
	if config.Mode == "" {
		config.Mode = "fast"
	}
	if config.Conn == 0 {
		config.Conn = 1
	}
	if config.ScavengeTTL == 0 {
		config.ScavengeTTL = 600
	}
	if config.MTU == 0 {
		config.MTU = 1350
	}
	if config.SndWnd == 0 {
		config.SndWnd = 128
	}
	if config.RcvWnd == 0 {
		config.RcvWnd = 512
	}
	if config.DataShard == 0 {
		config.DataShard = 10
	}
	if config.ParityShard == 0 {
		config.ParityShard = 3
	}
	if config.Interval == 0 {
		config.Interval = 50
	}
	if config.SockBuf == 0 {
		config.SockBuf = 4194304
	}
	if config.SmuxVer == 0 {
		config.SmuxVer = 1
	}
	if config.SmuxBuf == 0 {
		config.SmuxBuf = 4194304
	}
	if config.FrameSize == 0 {
		config.FrameSize = 8192
	}
	if config.StreamBuf == 0 {
		config.StreamBuf = 2097152
	}
	if config.KeepAlive == 0 {
		config.KeepAlive = 10
	}
	switch config.Mode {
	case "normal":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 40, 2, 1
	case "fast":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 30, 2, 1
	case "fast2":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 20, 2, 1
	case "fast3":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 10, 2, 1
	}

	// SMUX Version check
	if config.SmuxVer > maxSmuxVer {
		config.SmuxVer = maxSmuxVer
	}

	// Scavenge parameters check
	if config.AutoExpire != 0 && config.ScavengeTTL > config.AutoExpire {
	}
}

func (config *Config) NewBlock() (block kcp.BlockCrypt) {
	pass := pbkdf2.Key([]byte(config.Key), []byte(SALT), 4096, 32, sha1.New)
	switch config.Crypt {
	case "null":
		block = nil
	case "tea":
		block, _ = kcp.NewTEABlockCrypt(pass[:16])
	case "xor":
		block, _ = kcp.NewSimpleXORBlockCrypt(pass)
	case "none":
		block, _ = kcp.NewNoneBlockCrypt(pass)
	case "aes-128":
		block, _ = kcp.NewAESBlockCrypt(pass[:16])
	case "aes-192":
		block, _ = kcp.NewAESBlockCrypt(pass[:24])
	case "blowfish":
		block, _ = kcp.NewBlowfishBlockCrypt(pass)
	case "twofish":
		block, _ = kcp.NewTwofishBlockCrypt(pass)
	case "cast5":
		block, _ = kcp.NewCast5BlockCrypt(pass[:16])
	case "3des":
		block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
	case "xtea":
		block, _ = kcp.NewXTEABlockCrypt(pass[:16])
	case "salsa20":
		block, _ = kcp.NewSalsa20BlockCrypt(pass)
	case "aes-128-gcm":
		block, _ = kcp.NewAESGCMCrypt(pass[:16])
	default:
		config.Crypt = "aes"
		block, _ = kcp.NewAESBlockCrypt(pass)
	}
	return
}

// Normalize applies reference defaults, then checks allocation and duration bounds.
func (c *Config) Normalize() error {
	c.FillDefaults()
	for name, value := range map[string]int{"conn": c.Conn, "autoexpire": c.AutoExpire, "scavengettl": c.ScavengeTTL, "mtu": c.MTU, "ratelimit": c.RateLimit, "sndwnd": c.SndWnd, "rcvwnd": c.RcvWnd, "datashard": c.DataShard, "parityshard": c.ParityShard, "dscp": c.DSCP, "nodelay": c.NoDelay, "interval": c.Interval, "resend": c.Resend, "nc": c.NoCongestion, "sockbuf": c.SockBuf, "smuxver": c.SmuxVer, "smuxbuf": c.SmuxBuf, "framesize": c.FrameSize, "streambuf": c.StreamBuf, "keepalive": c.KeepAlive} {
		if value < 0 {
			return fmt.Errorf("negative kcptun %s", name)
		}
	}
	if c.Conn > 64 || c.MTU < 50 || c.MTU > 1500 || c.SndWnd > 65536 || c.RcvWnd > 65536 || c.DataShard > 256 || c.ParityShard > 256 || c.DataShard+c.ParityShard > 256 || c.DataShard < 1 || c.DSCP > 63 || c.Interval > 5000 || c.Interval < 1 || c.NoDelay > 1 || c.NoCongestion > 1 || c.SockBuf > 64<<20 || c.SmuxBuf > 64<<20 || c.StreamBuf > c.SmuxBuf || c.FrameSize > 65535 || c.SmuxVer < 1 || c.KeepAlive > 86400 || c.AutoExpire > 86400 || c.ScavengeTTL > 86400 || uint64(c.RateLimit) > math.MaxUint32 {
		return fmt.Errorf("kcptun option exceeds supported transport budget")
	}
	return nil
}
