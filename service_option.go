package vmess

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
