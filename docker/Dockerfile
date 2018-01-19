FROM alpine

ADD app/tg /tg

RUN apk --no-cache add ca-certificates && update-ca-certificates

ENTRYPOINT ["/tg"]
