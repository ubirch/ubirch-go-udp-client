ARG GOVERSION=1.16
FROM golang:$GOVERSION-alpine AS builder
COPY . /app
ARG GOARCH=amd64
ARG GOARM=7
ARG VERSION=devbuild
ARG REVISION=0000000
WORKDIR /app/main
RUN \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOPROXY=https://proxy.golang.org,direct \
    go build -trimpath -ldflags "-buildid= -s -w -X main.Version=$VERSION -X main.Revision=$REVISION" -o main .


FROM scratch
VOLUME /data
EXPOSE 8080/tcp
COPY docker/etc/ /etc/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder app/main/main ubirch-client
USER nobody:nogroup
ENTRYPOINT ["/ubirch-client"]
CMD ["/data"]
