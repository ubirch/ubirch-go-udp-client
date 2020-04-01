module github.com/ubirch/ubirch-go-udp-client/main

go 1.13

require (
	github.com/google/uuid v1.1.1
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lib/pq v1.3.0
	github.com/ubirch/ubirch-protocol-go/ubirch/v2 v2.0.5-0.20200325133254-da0590bcd15d
)

replace github.com/ubirch/ubirch-protocol-go/ubirch/v2 v2.0.5-0.20200325133254-da0590bcd15d => ../../ubirch-protocol-go/ubirch
