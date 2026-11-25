package script

import (
	"context"
	"runtime"
	"time"
)

// Services supplies optional native operations to a script session. A service
// shared between sessions must support concurrent calls.
type Services struct {
	HTTP   HTTPClient
	Store  Store
	Notify Notifier
	GeoIP  GeoIP
	Log    func(level, msg string) // nil disables console logging.
}

// HTTPClient sends requests made by $httpClient. Implementations should stop
// work when ctx is done and apply the individual request timeout.
type HTTPClient interface {
	Do(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error)
}

// DefaultHTTPRequestTimeout matches Surge's timeout for $httpClient requests.
const DefaultHTTPRequestTimeout = 5 * time.Second

// HTTPRequest contains the options supplied by $httpClient.
type HTTPRequest struct {
	Method, URL              string
	Headers                  []HeaderField
	Body                     []byte
	Timeout                  time.Duration
	Policy, PolicyDescriptor string
	Insecure                 bool
	AutoRedirect, AutoCookie bool
	Binary                   bool
}

// HTTPResponse contains the result of a request made by $httpClient.
type HTTPResponse struct {
	Status  int
	Headers []HeaderField
	Body    []byte
}

// Store is the backing store for $persistentStore.
type Store interface {
	Read(key string) (value string, ok bool, err error)
	Write(key, value string) error
	Delete(key string) error
}

// Notifier delivers $notification posts.
type Notifier interface {
	Post(n Notification)
}

// NotificationOptionsMax is Reka's budget for notification options in an event.
const NotificationOptionsMax = 8 << 10

// Notification is a message and its platform-specific options.
type Notification struct {
	Title, Subtitle, Body string
	Options               map[string]any
}

// GeoIP supplies IP address metadata for $utils.
type GeoIP interface {
	Country(ip string) string
	ASN(ip string) (uint32, bool)
	ASOrg(ip string) string
}

// Environment is the metadata exposed through $environment.
type Environment struct {
	System       string
	SurgeVersion string
	SurgeBuild   string
	Language     string
	DeviceModel  string
}

const (
	// DefaultSurgeVersion is the version advertised by Reka by default.
	DefaultSurgeVersion = "5.20.0"
	// DefaultSurgeBuild is the build advertised by Reka by default.
	DefaultSurgeBuild = "3000"
)

func (env Environment) withDefaults() Environment {
	if env.System == "" {
		switch runtime.GOOS {
		case "darwin":
			env.System = "macOS"
		case "ios":
			env.System = "iOS"
		case "windows":
			env.System = "Windows"
		case "android":
			env.System = "Android"
		default:
			env.System = runtime.GOOS
		}
	}
	// Community scripts use $environment["surge-version"] to detect the host.
	// Advertise Surge so they take the API branch this host implements.
	if env.SurgeVersion == "" {
		env.SurgeVersion = DefaultSurgeVersion
	}
	if env.SurgeBuild == "" {
		env.SurgeBuild = DefaultSurgeBuild
	}
	if env.Language == "" {
		env.Language = "en"
	}
	return env
}
