module github.com/nukilabs/utls

go 1.27

retract (
	v1.4.1 // #218
	v1.4.0 // #218 panic on saveSessionTicket
)

require (
	github.com/andybalholm/brotli v1.2.3
	github.com/klauspost/compress v1.19.2
	golang.org/x/crypto v0.55.0
	golang.org/x/net v0.57.0
	golang.org/x/sys v0.47.0
)

require golang.org/x/text v0.41.0 // indirect
