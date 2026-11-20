#!/bin/bash
# Install inert, dedicated unit definitions. Runtime and credentials are supplied separately.
set -euo pipefail
[[ $EUID == 0 ]] || { echo "Run as the host administrator." >&2; exit 1; }
src=$(cd -- "$(dirname -- "$0")" && pwd)
units=(shards-stage-kernel.service shards-stage-origin.service)
for unit in "${units[@]}"; do
    path=/etc/systemd/system/$unit
    if [[ -L $path || -e $path ]] && ! { [[ -f $path && ! -L $path ]] && cmp -s "$src/$unit" "$path"; }; then
        echo "Conflicting unit: $unit" >&2
        exit 1
    fi
    rc=0
    properties=$(systemctl show -p LoadState -p FragmentPath -p DropInPaths "$unit") || rc=$?
    if [[ $rc != 0 && ! ( $rc == 4 && $properties == *LoadState=not-found* ) ]]; then
        echo "Cannot inspect $unit in systemd." >&2
        exit 1
    fi
    while IFS= read -r property; do
        case "$property" in
            FragmentPath=|FragmentPath="$path"|DropInPaths=) ;;
            FragmentPath=*|DropInPaths=?*) echo "Conflicting systemd configuration for $unit." >&2; exit 1 ;;
        esac
    done <<< "$properties"
done
for unit in "${units[@]}"; do
    path=/etc/systemd/system/$unit
    if [[ ! -e $path ]]; then
        tmp=$(mktemp /etc/systemd/system/.shards-stage.XXXXXX)
        trap 'rm -f -- "$tmp"' EXIT
        install -m 0644 "$src/$unit" "$tmp"
        ln -T "$tmp" "$path"
        rm -f -- "$tmp"
        trap - EXIT
    fi
done
systemctl daemon-reload
