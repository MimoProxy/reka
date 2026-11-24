//go:build !ios

package compile

import "github.com/MimoProxy/reka/internal/httprewrite"

// MITMMaxBodySize follows Surge's desktop HTTP body rewrite limit.
const MITMMaxBodySize = httprewrite.DesktopMaxBodySize
