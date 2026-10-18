#!/bin/sh
# Install a built libauth and its headers into a staging root.
set -eu
build_dir=${1:?build directory required}
stage_dir=${2:?staging root required}
lib_dir=${3:-/usr/lib/x86_64-linux-peios}
case "$lib_dir" in /*) ;; *)
    echo "libdir must be absolute" >&2
    exit 1
    ;;
esac
source_dir=$(CDPATH="" cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$stage_dir$lib_dir/pkgconfig" "$stage_dir/usr/include/peios"
cp -f "$build_dir/libauth.so" "$stage_dir$lib_dir/libauth.so.1"
ln -sfn libauth.so.1 "$stage_dir$lib_dir/libauth.so"
cp -f "$source_dir"/libauth/include/peios/auth*.h "$stage_dir/usr/include/peios/"
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$source_dir/libauth/Cargo.toml")
cat >"$stage_dir$lib_dir/pkgconfig/auth.pc" <<PC
prefix=/usr
libdir=$lib_dir
includedir=\${prefix}/include

Name: auth
Description: Peios authentication client library
Version: $version
Libs: -L\${libdir} -lauth
Cflags: -I\${includedir}
PC
