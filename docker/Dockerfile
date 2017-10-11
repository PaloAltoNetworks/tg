FROM alpine

ADD tg /tg

RUN apk --no-cache add ca-certificates && update-ca-certificates

ENTRYPOINT ["/tg"]
