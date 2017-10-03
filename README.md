# tg

tg (short for tlsgen, and also a french pun) makes issuing certificates easy. It only used the standard golang crypto lib.

## Install

    go get -u github.com/aporeto-inc/tg

## Examples

To generate a self signed certificate server certificate:

    tg --name mycert --org acme --common-name john --auth-server

To generate a CA:

    tg --name myca --org acme --common-name root --is-ca --pass secret

To issue a client certificate from a CA:

    tg --name myclient --org acme --common-name client
        --auth-client \
        --signing-cert myca-cert.pem \
        --signing-cert-key myca-key.pem \
        --signing-cert-key-pass secret

Lot's of additional options:

    tg -h

> NOTE: all parameters can be given using env variables. Prefix the argument with `TLSGEN_`. for instance `TLSGEN_OUT` for setting output dir.
