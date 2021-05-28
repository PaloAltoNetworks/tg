# tg

[![Codacy Badge](https://app.codacy.com/project/badge/Grade/5c44c0a92a4e44959feccfd28f2b485a)](https://www.codacy.com/gh/PaloAltoNetworks/tg/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=PaloAltoNetworks/tg&amp;utm_campaign=Badge_Grade) [![Codacy Badge](https://app.codacy.com/project/badge/Coverage/5c44c0a92a4e44959feccfd28f2b485a)](https://www.codacy.com/gh/PaloAltoNetworks/tg/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=PaloAltoNetworks/tg&amp;utm_campaign=Badge_Coverage)

tg (short for tlsgen, and also a french pun) makes issuing certificates easy. It only used the standard golang crypto lib (but for generating pkcs12, as go doesn't provide a way to write them. If you want the --p12 option to work, you need openssl installed.)

## Install

    go get -u github.com/aporeto-inc/tg

## Examples

To generate a self signed server certificate:

    % tg cert --name mycert --org acme --common-name john --auth-server
    INFO[0000] certificate key pair created             cert=mycert-cert.pem key=mycert-key.pem

To generate a CA:

    % tg cert --name myca --org acme --common-name root --is-ca --pass secret
    INFO[0000] certificate key pair created             cert=myca-cert.pem key=myca-key.pem

To issue a client certificate from a CA:

    % tg cert --name myclient --org acme --common-name client \
        --auth-client \
        --signing-cert myca-cert.pem \
        --signing-cert-key myca-key.pem \
        --signing-cert-key-pass secret
    INFO[0000] certificate key pair created             cert=myclient-cert.pem key=myclient-key.pem

To verify a certificate:

    % tg verify --cert myclient-cert.pem --signer myca-cert.pem
    INFO[0000] certificate verified

To generate a CSR and a private key:

    % tg csr --name myreq --org acme --common-name client
    INFO[0000] Certificate request and private key created   csr=myreq-csr.pem key=myreq-key.pem

To sign a CSR:

    % tg sign --name newcert --csr myreq-csr.pem \
        --auth-server \
        --signing-cert myca-cert.pem \
        --signing-cert-key myca-key.pem \
        --signing-cert-key-pass secret
    INFO[0000] Certificate issued                            cert=newcert-cert.pem

To encrypt a private key:

    % tg encrypt --key myclient-key.pem --pass secret > myclient-key.pem.enc

To decrypt a private key:

    % tg decrypt --key myclient-key.pem.enc --pass secret

Lot's of additional options:

    tg -h

> NOTE: all parameters can be given using env variables. Prefix the argument with `TLSGEN_`. for instance `TLSGEN_OUT` for setting output dir.
