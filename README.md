# Speak friend or enter

Mellon, a testbed for OAuth technology.

# Building

To build Mellon, you need Go, `openssl` and some other packages
installed. Below is the installation command for [Arch
Linux](https://archlinux.org/):

```text
# pacman -Syu \
    go \
    golangci-lint \
    make \
    openssl \
    ;
```

You can now build mellon with:
```text
$ make build
```

# Running

First, you need a set of certificates. This only needs to be done
once.  To create the certificates you need, you can use the command
below to:

- CA certificate
- Server certificate and key
- Client certificate, key and bundle to be used in the web browser.

```text
$ make certs
```

You can now run Mellon with:

```text
$ make run
```

# Creating additional client certificates

Here, I create a client certificate and key for using in the browser,
with subject `browser` (`CN=browser/OU=hobbit/O=skybert`):

```text
$ openssl \
    req \
    -newkey rsa:2048 \
    -nodes \
    -keyout browser.key \
    -out browser.csr \
    -subj "/CN=browser/OU=hobbit/O=skybert"
```
```text
$ openssl \
    x509 \
    -req \
    -in browser.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out "browser.crt" \
    -days 825 \
    -sha256 \
    -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n")
```
```text
$  openssl \
    pkcs12 \
    -export \
    -out browser.p12 \
    -inkey browser.key \
    -in browser.crt \
    -certfile ca.crt \
    -name "browser client" \
    -passout pass:changeit

```

# AI policy

No AI generated code. Everything that a human will read, is written by
a human.

