package vmess

import (
	"time"

	N "github.com/sagernet/sing/common/network"
)

type ServiceOption func(service *Service[string])

func ServiceWithTimeFunc(timeFunc TimeFunc) ServiceOption {
	return func(service *Service[string]) {
		service.time = timeFunc
	}
}

func ServiceWithDisableHeaderProtection() ServiceOption {
	return func(service *Service[string]) {
		service.disableHeaderProtect = true
	}
}

// ServiceWithAuthScanLimit limits, per source address, how many connections
// may scan all users and still match none: up to burst at once, refilled at
// perSecond. Users that recently authenticated from a source are tried first
// and are never limited. A burst of zero or less disables the limit.
func ServiceWithAuthScanLimit(burst int, perSecond float64) ServiceOption {
	return func(service *Service[string]) {
		service.sources = newSourceCache(burst, perSecond)
	}
}

// ServiceWithFallback hands every request that cannot be served to handler,
// with the bytes read so far replayed, for example to a web server. Without
// one such connections are drained until the peer closes or the handshake
// deadline passes.
func ServiceWithFallback(handler N.TCPConnectionHandlerEx) ServiceOption {
	return func(service *Service[string]) {
		service.fallbackHandler = handler
	}
}

// ServiceWithHandshakeTimeout bounds reading the request header. Zero or less
// keeps the default: DefaultHandshakeTimeout, or
// DefaultFallbackHandshakeTimeout with a fallback.
func ServiceWithHandshakeTimeout(timeout time.Duration) ServiceOption {
	return func(service *Service[string]) {
		if timeout > 0 {
			service.handshakeTimeout = timeout
		}
	}
}

// ServiceWithRequireEncryption rejects requests whose body is unencrypted
// ("none") or unauthenticated ("aes-128-cfb"). Use it when no outer TLS
// protects the connection; such requests then take the fallback path.
func ServiceWithRequireEncryption() ServiceOption {
	return func(service *Service[string]) {
		service.requireEncryption = true
	}
}

// ServiceWithResponseShaping enables ResponseShapingOptions; zero fields use
// the defaults.
func ServiceWithResponseShaping(options ResponseShapingOptions) ServiceOption {
	return func(service *Service[string]) {
		service.responseShaping = normalizeResponseShaping(options)
	}
}
