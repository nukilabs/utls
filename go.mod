module github.com/nukilabs/utls

go 1.26

retract (
	v1.4.1 // #218
	v1.4.0 // #218 panic on saveSessionTicket
)

require (
	github.com/andybalholm/brotli v1.2.2
	github.com/klauspost/compress v1.19.0
	golang.org/x/crypto v0.53.0
	golang.org/x/net v0.55.0
	golang.org/x/sys v0.46.0
)

require golang.org/x/text v0.38.0 // indirect
