#!/usr/bin/env bash

DIR="$(dirname "$(readlink -f "$0")")"

${CONTAINER_ENGINE:-podman} build -f ${DIR}/Containerfile -t nimbusds-fips:latest .
