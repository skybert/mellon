#! /usr/bin/env bash

## author: torstein, torstein@skybert.net

set -o errexit
set -o nounset
set -o pipefail

main() {
  local _cwd=
  _cwd="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

  cd "${_cwd}"/.. || exit 1

  curl \
    --cacert etc/certs/ca.crt \
    --cert etc/certs/client.crt \
    --key etc/certs/client.key \
    https://mellon.skybert:9443/ping
}

main "$@"
