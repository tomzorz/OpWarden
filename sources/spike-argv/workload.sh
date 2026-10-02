#!/usr/bin/env bash
# Reproduces the caller-resolution break, without touching 1Password.
#
# Each nested `bash -c` is an MSYS2-to-MSYS2 exec, and each one retires the
# process holding the parent link. The leaf is the spike logger (native), so its
# own parent stub survives and everything above it is already gone. That is the
# exact shape a just-driven MSYS2 workflow produces, minus the secrets.
set -u

bash -c 'bash -c "op --version > /dev/null"'
