package script

import "time"

const (
	// DefaultTimeout is the same as Surge's default script timeout.
	DefaultTimeout = 5 * time.Second
	// DefaultMaxSize is Surge's macOS default body limit, also used by httprewrite.
	DefaultMaxSize = 10 << 20
	// defaultConcurrency matches the maximum parallel sessions in Surge's JSC engine.
	defaultConcurrency = 2
	// defaultHardMaxSize matches Surge's hard body limit even with max-size=-1.
	defaultHardMaxSize = 32 << 20
	// defaultMaxTimers matches Surge's limit on pending timers per session.
	defaultMaxTimers = 64
	// defaultMaxHTTPInFlight matches Surge's limit on concurrent requests per session.
	defaultMaxHTTPInFlight = 64
	// defaultLogLineMax matches Surge's maximum log line size.
	defaultLogLineMax = 512 << 10
	// DefaultStoreValueMax matches Surge's iOS limit on one persistent store value.
	DefaultStoreValueMax = 4 << 20
	// defaultCacheBytes is Reka's budget for roughly 3 MiB of source, based on
	// measured compiled programs occupying about ten times as many bytes.
	defaultCacheBytes = 32 << 20
	// defaultBreakerFailures is Reka's threshold for opening a script circuit.
	defaultBreakerFailures = 3
	// defaultBreakerCooldown is Reka's interval before allowing a trial run.
	defaultBreakerCooldown = time.Minute
)

// Limits bounds HTTP script execution. Nonpositive values use defaults.
type Limits struct {
	Concurrency     int
	HardMaxSize     int64
	UngzipMax       int64
	MaxTimers       int
	MaxHTTPInFlight int
	LogLineMax      int
	StoreValueMax   int
	CacheBytes      int64
	BreakerFailures int
	BreakerCooldown time.Duration
}

// DefaultLimits returns the default settings for a host.
func DefaultLimits() Limits {
	return (Limits{}).WithDefaults()
}

// WithDefaults fills in limits that have no positive value.
func (l Limits) WithDefaults() Limits {
	if l.Concurrency <= 0 {
		l.Concurrency = defaultConcurrency
	}
	if l.HardMaxSize <= 0 {
		l.HardMaxSize = defaultHardMaxSize
	}
	if l.UngzipMax <= 0 {
		// Surge caps ungzip at 16 MiB on iOS and 128 MiB on macOS. Reka uses
		// its effective hard body limit to bound the amount of decoded data.
		l.UngzipMax = l.HardMaxSize
	}
	if l.MaxTimers <= 0 {
		l.MaxTimers = defaultMaxTimers
	}
	if l.MaxHTTPInFlight <= 0 {
		l.MaxHTTPInFlight = defaultMaxHTTPInFlight
	}
	if l.LogLineMax <= 0 {
		l.LogLineMax = defaultLogLineMax
	}
	if l.StoreValueMax <= 0 {
		l.StoreValueMax = DefaultStoreValueMax
	}
	if l.CacheBytes <= 0 {
		l.CacheBytes = defaultCacheBytes
	}
	if l.BreakerFailures <= 0 {
		l.BreakerFailures = defaultBreakerFailures
	}
	if l.BreakerCooldown <= 0 {
		l.BreakerCooldown = defaultBreakerCooldown
	}
	return l
}
