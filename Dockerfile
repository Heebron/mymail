FROM golang:1.27 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN GOWORK=off go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /mymail ./cmd/mymail

FROM backplane/upx:latest AS compressed

COPY --from=build /mymail /mymail
RUN upx --best /mymail

FROM scratch

COPY --from=compressed /mymail /mymail

ENTRYPOINT ["/mymail"]