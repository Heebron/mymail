#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_root=$(cd -- "$script_dir/.." && pwd)

exec go run "$project_root/cmd/mymail-send" \
  -server "${MYMAIL_SMTP_SERVER:-127.0.0.1:2525}" \
  -from "kpratt@leopard.thepratts.info" \
  -to "kpratt@leoperd.thepratts.info" \
  -username "kpratt" \
  -password "changeit"