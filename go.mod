module github.com/florianl/go-nfqueue

// DEPRECATED: This module version is deprecated. Please upgrade to github.com/florianl/go-nfqueue/v2.
// All v1.x versions are retracted as they are no longer maintained.
retract (
	[v1.0.0, v1.3.3] // All v1.x versions are deprecated and no longer maintained
)

require (
	github.com/mdlayher/netlink v1.7.2
	golang.org/x/sys v0.20.0
)

require (
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	golang.org/x/net v0.25.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
)

go 1.18
