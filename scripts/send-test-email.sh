#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_root=$(cd -- "$script_dir/.." && pwd)

exec go run "$project_root/cmd/mymail-send" \
  -server "${MYMAIL_SMTP_SERVER:-127.0.0.1:587}" \
  -from "kpratt@leopard.thepratts.info" \
  -to "kenpratt@comcast.net" \
  -to "kenpratt01@comcast.net" \
  -to "stashcan@comcast.net" \
  -to "jesterfred@gmail.com"
