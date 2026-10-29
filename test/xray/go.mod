module github.com/sagernet/sing-vmess/test/xray

go 1.26

require (
	github.com/sagernet/sing v0.7.8-0.20250909124511-ab3827767cea
	github.com/sagernet/sing-vmess v0.0.0
	github.com/xtls/xray-core v1.260327.0
)

require (
	github.com/gofrs/uuid/v5 v5.3.2 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/sagernet/sing-vmess => ../..
