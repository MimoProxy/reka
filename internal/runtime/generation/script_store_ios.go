package generation

// Reka uses smaller limits to stay within the Packet Tunnel memory budget.
const (
	scriptStoreValueMax = 256 << 10
	scriptStoreTotalMax = 1 << 20
)
