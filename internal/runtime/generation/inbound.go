package generation

import (
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
)

func (e *Engine) newInbound(config compile.Listener) (*sagernet.Inbound, error) {
	users := make([]sagernet.InboundUser, len(config.Users))
	for i, user := range config.Users {
		users[i] = sagernet.InboundUser{Username: user.Username, Password: user.Password}
	}
	return e.backend.NewInboundWithUsers(config.ID, config.Type, config.Listen, users)
}
