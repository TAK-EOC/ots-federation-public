#!/usr/bin/env bash
# regen.sh — Regenerate Python protobuf stubs from fig.proto
#
# Source proto: vendor/tak-server-official @ commit 5187abd
# Proto path:   src/takserver-protobuf/src/main/proto/fig.proto
#
# GENCODE VERSION CEILING — READ BEFORE CHANGING grpcio-tools VERSION:
#   OTS pins protobuf==6.33.1 exactly (no flexibility).
#   The generated _pb2.py files call ValidateProtobufRuntimeVersion(major, minor, patch).
#   This check fails if gencode_version > runtime_version (patch-level comparison).
#   grpcio-tools 1.71.x (and earlier) use protobuf 5.29.x, which generates
#   ValidateProtobufRuntimeVersion(5, 29, 0, ...). Because 5.29.0 < 6.33.1,
#   the runtime check passes under OTS's pin.
#   grpcio-tools 1.72.x+ switch to protobuf 6.33.6 and generate
#   ValidateProtobufRuntimeVersion(6, 33, 6, ...) — incompatible with runtime 6.33.1.
#   DO NOT upgrade grpcio-tools past 1.71.x unless OTS's protobuf pin also moves.
#   See ticket 25b4aa for root-cause analysis.
#
# Build deps (pinned, build-time only — NOT runtime):
#   grpcio-tools==1.71.0  (brings protobuf==5.29.6; emits gencode version 5.29.0)
#
# Usage:
#   cd <repo root>
#   python3 -m venv /tmp/proto-regen-venv
#   source /tmp/proto-regen-venv/bin/activate
#   pip install grpcio-tools==1.71.0
#   ./ots_federation/proto/regen.sh
#   deactivate && rm -rf /tmp/proto-regen-venv
#
# Note: grpcio-tools is a build-time dependency only. The generated _pb2.py files
# are committed to source so that runtime containers do not need grpcio-tools.
# The runtime package only needs grpcio==1.81.1 and protobuf>=6.33.1,<7.0.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../" && pwd)"
PROTO_SRC="${PROJECT_ROOT}/../vendor/tak-server-official/src/takserver-protobuf/src/main/proto"
OUT_DIR="${SCRIPT_DIR}"

# Resolve absolute path of vendor proto source
if [ ! -d "${PROTO_SRC}" ]; then
    echo "ERROR: Proto source not found at ${PROTO_SRC}" >&2
    echo "       Clone vendor/tak-server-official first." >&2
    exit 1
fi

echo "Generating from: ${PROTO_SRC}"
echo "Output to:       ${OUT_DIR}"
echo "Source commit:   5187abd (tak-server-official)"

python -m grpc_tools.protoc \
    -I"${PROTO_SRC}" \
    --python_out="${OUT_DIR}" \
    --grpc_python_out="${OUT_DIR}" \
    "${PROTO_SRC}/fig.proto" \
    "${PROTO_SRC}/binarypayload.proto"

echo "Done. Generated files:"
ls -1 "${OUT_DIR}"/*.py
