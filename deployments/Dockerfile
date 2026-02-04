# SPDX-License-Identifier: Apache-2.0
# Copyright 2024 BOANLab @ DKU

# Build Stage
FROM golang:1.23.4-alpine3.20 AS builder

WORKDIR /app

COPY KubeWard/ .

RUN go build -o KubeWard main.go

# Run Stage
FROM alpine:3.20

WORKDIR /app

COPY --from=builder /app/KubeWard .

CMD ["./KubeWard"]
