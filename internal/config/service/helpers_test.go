package service

import "github.com/MimoProxy/reka/internal/backend/sagernet"

func backendOptions() sagernet.Options { return sagernet.Options{Logger: quiet()} }
