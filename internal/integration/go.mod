module github.com/florianl/go-nfqueue/v2/internal/integration

go 1.26.0

require (
	github.com/florianl/go-nfqueue/v2 v2.0.0
	github.com/jsimonetti/rtnetlink/v2 v2.2.0
	golang.org/x/sync v0.25.0
	golang.org/x/sys v0.45.0
)

require (
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.6.0 // indirect
	golang.org/x/net v0.55.0 // indirect
)

replace github.com/florianl/go-nfqueue/v2 => ../../
