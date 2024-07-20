FROM golang:1.22-alpine AS build

WORKDIR /root
COPY go.mod /root
COPY main.go /root

RUN cd /root && go mod tidy && go build -o main

FROM scratch AS run
LABEL authors="Nicko van Someren"

VOLUME /uploads

COPY --from=build /root/main /root/main

CMD ["/root/main"]
