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





