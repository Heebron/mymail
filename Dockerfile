FROM golang:1.27 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN GOWORK=off go mod download

COPY . .
ARG VERSION=devel
ARG BUILT_ON=unknown
RUN GOWORK=off CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.builtOn=${BUILT_ON}" -o /mymail ./cmd/mymail

FROM backplane/upx:latest AS compressed

COPY --from=build /mymail /mymail
RUN upx --best /mymail

FROM scratch

COPY --from=compressed /mymail /mymail

ENTRYPOINT ["/mymail"]