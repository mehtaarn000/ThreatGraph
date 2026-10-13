FROM golang:1.25-alpine AS build

WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/threatgraph-api ./cmd/api

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/threatgraph-api /threatgraph-api
EXPOSE 8080
ENTRYPOINT ["/threatgraph-api"]
