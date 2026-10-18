#!/bin/sh
# Sourced by Pekit's vendor, main and test commands. No ambient SDK lookup in Bazel.

prepare_native_sdk() {
    pkg-config --atleast-version=0.5.8 peios || {
        echo 'authd requires libpeios >= 0.5.8 (ABI 0)' >&2
        return 1
    }
    peios_libdir=$(pkg-config --variable=libdir peios)
    peios_includedir=$(pkg-config --variable=includedir peios)
    readelf -dW "$peios_libdir/libpeios.so" |
        grep -E '\(SONAME\).*\[libpeios\.so\.0\]' >/dev/null
    export PEIOS_SDK="$PEKIT_OUT/native-sdk"
    mkdir -p "$PEIOS_SDK/include" "$PEIOS_SDK/lib"
    ln -sfn "$peios_includedir/peios.h" "$PEIOS_SDK/include/peios.h"
    ln -sfn "$peios_includedir/peios" "$PEIOS_SDK/include/peios"
    ln -sfn /usr/include/pkm "$PEIOS_SDK/include/pkm"
    ln -sfn "$peios_libdir/libpeios.so.0" "$PEIOS_SDK/lib/libpeios.so.0"
    export PEIOS_RUSTC=/usr/bin/rustc
}

native_bazel() {
    python3 tools/bazel-vendor.py view "$PEKIT_VENDOR_OUT/bazel-vendor" "$PEKIT_OUT/bazel-vendor"
    operation=$1
    shift
    PEIOS_BAZEL_BINARY="$PEKIT_VENDOR_OUT/tools/bazel" \
        ./bazel --batch --output_base="$PEKIT_OUT/bazel-output" \
        --install_base="$PEKIT_OUT/bazel-install" "$operation" \
        --config=peios --vendor_dir="$PEKIT_OUT/bazel-vendor" \
        --repository_cache="$PEKIT_OUT/bazel-repository-cache" \
        --repository_disable_download --lockfile_mode=error "$@"
}
