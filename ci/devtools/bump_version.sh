#!/bin/bash

set -eEuox pipefail

KOMODOD_VERISON_OLD="${KOMODOD_VERISON_OLD:-5.0.0}"
KOMODOD_VERSION_NEW="${KOMODOD_VERSION_NEW:-5.0.1}"

bsd_sed=""
[ "$(uname -s)" = "Darwin" ] && bsd_sed=" ''"

# bump komodod version
sed -i${bsd_sed} "s/KOMODO_COMMITTISH=v${KOMODOD_VERISON_OLD}/KOMODO_COMMITTISH=v${KOMODOD_VERSION_NEW}/g" .travis.yml Dockerfile
sed -i${bsd_sed} "s/KOMODO_COMMITTISH?=v${KOMODOD_VERISON_OLD}/KOMODO_COMMITTISH?=v${KOMODOD_VERSION_NEW}/g" Makefile
sed -i${bsd_sed} "s/\"${KOMODOD_VERISON_OLD}\"/\"${KOMODOD_VERSION_NEW}\"/g" services/network_service_test.go services/types.go

