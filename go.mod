module github.com/nukilabs/utls

go 1.24

retract (
	v1.4.1 // #218
	v1.4.0 // #218 panic on saveSessionTicket
)

require (
	github.com/andybalholm/brotli v1.2.0
	github.com/cloudflare/circl v1.6.1
	github.com/klauspost/compress v1.18.0
	golang.org/x/crypto v0.40.0
	golang.org/x/net v0.42.0
	golang.org/x/sys v0.34.0
)

require golang.org/x/text v0.27.0 // indirect
