package compile

import (
	"fmt"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
)

func (c *compiler) listenerUsers(doc, path string, input []model.ListenerUser) []model.ListenerUser {
	if len(input) > 1024 {
		c.errorf(doc, path, "listener.users", "listener authentication exceeds 1024 users")
		return nil
	}
	out := make([]model.ListenerUser, 0, len(input))
	seen := map[string]bool{}
	for i, user := range input {
		base := fmt.Sprintf("%s/#%d", path, i)
		user.Username = c.listenerSecret(doc, base+"/username", user.Username)
		user.Password = c.listenerSecret(doc, base+"/password", user.Password)
		if user.Username == "" || len(user.Username) > 255 || strings.ContainsAny(user.Username, ":\r\n\x00") {
			if !c.hasErrorAt(base + "/username") {
				c.errorf(doc, base+"/username", "listener.users", "username must contain 1..255 bytes without colon or control characters")
			}
		}
		if user.Password == "" || len(user.Password) > 255 || strings.ContainsAny(user.Password, "\r\n\x00") {
			if !c.hasErrorAt(base + "/password") {
				c.errorf(doc, base+"/password", "listener.users", "password must contain 1..255 bytes without control characters")
			}
		}
		if seen[user.Username] {
			c.errorf(doc, base+"/username", "listener.users", "duplicate authentication username")
		}
		seen[user.Username] = true
		out = append(out, user)
	}
	return out
}

func (c *compiler) listenerSecret(doc, path, value string) string {
	start := len(c.diags)
	out := c.resolveSecret(path, value)
	if doc == model.DocLocal {
		for i := start; i < len(c.diags); i++ {
			c.diags[i].Document = doc
			if p, ok := c.lpos[c.diags[i].Path]; ok {
				c.diags[i].Line, c.diags[i].Column = p.Line, p.Column
			}
		}
	}
	return out
}
