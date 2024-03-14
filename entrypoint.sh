#!/bin/bash

set -euo pipefail

if [ "$(stat -c '%u:%g' /data)" != "65534:65534" ]; then
  echo "Folder mounted at /data is not owned by nobody:nogroup, please change it's permissions on the host with 'sudo chown -R 65534:65534 path/to/komodo-data'."
  exit 1
fi

if [ "${MODE:-x}" = "ONLINE" ]; then
  /app/fetch-params.sh
fi

args_kept=""
# parse args
for arg in "$@"; do
  case "$arg" in
    -e=*|-extend-kmd-conf=*)
      cat "/app/komodo-${NETWORK,,}.conf_default" > "/app/komodo-${NETWORK,,}.conf"
      echo -e "${arg#*=}" >> "/app/komodo-${NETWORK,,}.conf"
      shift
      ;;
    *)
      args_kept+="${arg} "
      shift
      ;;
  esac
done

set -- $args_kept
exec "$@"
