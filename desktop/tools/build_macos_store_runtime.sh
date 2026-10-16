#!/bin/bash
# Build a private, offline Store-tooling component, not a signed application.
set -euo pipefail
umask 077

if [ "$#" -ne 7 ]; then
    echo 'Usage: build_macos_store_runtime.sh RUBY_SOURCE OPENSSL_SOURCE LIBYAML_SOURCE GEM_CACHE CA_FILE ABSENT_OUTPUT arm64|x86_64' >&2
    exit 64
fi
if [ "$(/usr/bin/uname -s)" != Darwin ] || [ "$(/usr/bin/id -u)" = 0 ]; then
    echo 'Use an ordinary account on a native macOS build runner.' >&2; exit 69
fi
case "$7" in arm64) openssl_target=darwin64-arm64-cc ;; x86_64) openssl_target=darwin64-x86_64-cc ;; *) exit 64 ;; esac
[ "$(/usr/bin/uname -m)" = "$7" ] || { echo 'Build each architecture on its matching native runner.' >&2; exit 69; }
case "$6" in /*) output="$6" ;; *) echo 'Output must be absolute.' >&2; exit 64 ;; esac
[ ! -e "$output" ] && [ ! -L "$output" ] || { echo 'Output already exists; refusing overwrite.' >&2; exit 73; }
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository="$(cd -- "$here/../.." && pwd -P)"
ruby_source="$(cd -- "$1" && pwd -P)"
openssl_source="$(cd -- "$2" && pwd -P)"
yaml_source="$(cd -- "$3" && pwd -P)"
cache="$(cd -- "$4" && pwd -P)"
ca="$(cd -- "$(dirname -- "$5")" && pwd -P)/$(basename -- "$5")"
[ -f "$ca" ] && [ ! -L "$ca" ] || { echo 'Supply an authenticated regular CA bundle.' >&2; exit 65; }
/usr/bin/grep -Eq '^#define RUBY_API_VERSION_MAJOR +3$' "$ruby_source/include/ruby/version.h"
/usr/bin/grep -Eq '^#define RUBY_API_VERSION_MINOR +3$' "$ruby_source/include/ruby/version.h"
/usr/bin/grep -Eq '^#define RUBY_VERSION_TEENY +12$' "$ruby_source/version.h"
/usr/bin/grep -Eq '^MAJOR=3$' "$openssl_source/VERSION.dat"
/usr/bin/grep -Eq '^MINOR=5$' "$openssl_source/VERSION.dat"
/usr/bin/grep -Eq '^PATCH=8$' "$openssl_source/VERSION.dat"
/usr/bin/grep -Fq 'PACKAGE_VERSION='\''0.2.5'\''' "$yaml_source/configure"
sdk="$(/usr/bin/xcrun --sdk macosx --show-sdk-path)"
compiler="$(/usr/bin/xcrun --sdk macosx --find clang)"
scratch="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/mrk-store-runtime.XXXXXX")"
trap '/bin/rm -rf -- "$scratch"' EXIT
/bin/mkdir "$scratch/home" "$scratch/tmp" "$scratch/openssl" "$scratch/yaml" "$scratch/ruby"
prefix="$scratch/runtime"
dependencies="$scratch/dependencies"
architecture="$7"
python="$(command -v python3)"
run() {
    /usr/bin/env -i HOME="$scratch/home" TMPDIR="$scratch/tmp" \
        PATH="$prefix/bin:/usr/bin:/bin:/usr/sbin:/sbin" LANG=en_US.UTF-8 \
        SDKROOT="$sdk" MACOSX_DEPLOYMENT_TARGET=26.0 CC="$compiler" \
        CFLAGS="-O2 -arch $architecture" LDFLAGS="-arch $architecture" \
        GEM_HOME="$prefix/lib/ruby/gems/3.3.0" GEM_PATH="$prefix/lib/ruby/gems/3.3.0" \
        BUNDLE_IGNORE_CONFIG=1 BUNDLE_FROZEN=true BUNDLE_AUTO_INSTALL=false \
        BUNDLE_FORCE_RUBY_PLATFORM=true BUNDLE_PATH="$prefix/bundle" \
        BUNDLE_GEMFILE="$prefix/tooling/Gemfile" BUNDLE_RETRY=0 \
        SSL_CERT_FILE="$ca" FASTLANE_OPT_OUT_USAGE=true FASTLANE_SKIP_UPDATE_CHECK=true \
        FASTLANE_HIDE_CHANGELOG=true FASTLANE_SKIP_DOCS=true "$@"
}
(cd "$scratch/openssl"; run /usr/bin/perl "$openssl_source/Configure" "$openssl_target" \
    no-shared no-module no-tests --prefix="$dependencies" --openssldir=/mrk-no-system-openssl-config
    run /usr/bin/make -j2 build_libs; run /usr/bin/make install_dev)
(cd "$scratch/yaml"; run /bin/sh "$yaml_source/configure" --prefix="$dependencies" --disable-shared --enable-static
    run /usr/bin/make -j2; run /usr/bin/make install)
(cd "$scratch/ruby"; run /bin/sh "$ruby_source/configure" --prefix="$prefix" \
    --enable-load-relative --disable-shared --disable-install-doc --disable-yjit --disable-rjit \
    --with-openssl-dir="$dependencies" --with-libyaml-dir="$dependencies" --without-git
    run /usr/bin/make -j2
    # install/install-nodoc would run prepare-gems -> update-gems (network).
    # These upstream targets install Ruby, default gems and extensions only.
    run /usr/bin/make install-bin install-lib install-ext INSTRUBY_OPTS=--exclude=bundled-gems)

# The core requires its schemas/templates as well as Gemfile and Fastlane.
# This copies the actual first-party REQUIRED_TOOLING_FILES roster, without
# importing/executing any downloaded Ruby or relaxing core completeness checks.
run "$python" -I -B "$here/prepare_macos_store_inputs.py" --tooling-only "$prefix/tooling"
/bin/mkdir -p "$prefix/tooling/vendor/cache" "$prefix/licenses"
/usr/bin/install -m 0644 "$ca" "$prefix/ca.pem"
/usr/bin/install -m 0644 "$ruby_source/COPYING" "$prefix/licenses/Ruby-COPYING"
/usr/bin/install -m 0644 "$ruby_source/BSDL" "$prefix/licenses/Ruby-BSDL"
/usr/bin/install -m 0644 "$ruby_source/LEGAL" "$prefix/licenses/Ruby-LEGAL"
/usr/bin/install -m 0644 "$openssl_source/LICENSE.txt" "$prefix/licenses/OpenSSL-LICENSE.txt"
/usr/bin/install -m 0644 "$yaml_source/License" "$prefix/licenses/LibYAML-License"
bundler="$cache/bundler-4.0.16.gem"
expected="$(/usr/bin/plutil -extract bundler.sha256 raw -o - "$repository/.github/verification-tools.json")"
[ -f "$bundler" ] && [ ! -L "$bundler" ]
[ "$(/usr/bin/shasum -a 256 "$bundler" | /usr/bin/awk '{print $1}')" = "$expected" ]
# Ruby installs a default Bundler launcher in bin/bundle. Install the locked
# Bundler's unused generated launchers into fresh private scratch, not over it.
/bin/mkdir "$scratch/bundler-cli"
run "$prefix/bin/ruby" "$prefix/bin/gem" install --local --no-document --ignore-dependencies \
    --bindir "$scratch/bundler-cli" "$bundler"
# Copy only ordinary local gem archives. Bundler checks selected lock checksums;
# a missing dependency is an error, never a request to download it.
count=0
for gem in "$cache"/*.gem; do
    [ -f "$gem" ] && [ ! -L "$gem" ] || exit 65
    count=$((count + 1)); [ "$count" -le 200 ] || exit 65
    /usr/bin/install -m 0644 "$gem" "$prefix/tooling/vendor/cache/"
done
bundle="$prefix/lib/ruby/gems/3.3.0/gems/bundler-4.0.16/exe/bundle"
run "$prefix/bin/ruby" "$bundle" install --local --jobs 2 --retry 0
# Executable gem shebangs contain the build prefix. The Store entry uses only
# ruby and this relocatable bundle wrapper, never an arbitrary cached binstub.
cat > "$prefix/bin/bundle" <<'WRAPPER'
#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
unset RUBYOPT RUBYLIB GEMRC
export GEM_HOME="$root/lib/ruby/gems/3.3.0" GEM_PATH="$root/lib/ruby/gems/3.3.0"
export BUNDLE_IGNORE_CONFIG=1 BUNDLE_FROZEN=true BUNDLE_AUTO_INSTALL=false
export BUNDLE_GEMFILE="$root/tooling/Gemfile" BUNDLE_PATH="$root/bundle"
export BUNDLE_FORCE_RUBY_PLATFORM=true SSL_CERT_FILE="$root/ca.pem"
exec "$root/bin/ruby" "$GEM_HOME/gems/bundler-4.0.16/exe/bundle" "$@"
WRAPPER
/bin/chmod 0755 "$prefix/bin/bundle"
# Archive caches are build-only; installed gem sources/licenses are retained.
/bin/rm -rf -- "$prefix/tooling/vendor/cache"
/bin/rmdir "$prefix/tooling/vendor"
run "$prefix/bin/bundle" check
run "$prefix/bin/bundle" exec ruby "$here/verify_macos_store_runtime.rb" "$prefix" "$architecture" trim-notifier
run "$prefix/bin/ruby" --disable=gems "$here/verify_macos_store_runtime.rb" "$prefix" "$architecture" default
run "$prefix/bin/bundle" exec ruby "$here/verify_macos_store_runtime.rb" "$prefix" "$architecture" bundle
/bin/mv "$prefix" "$scratch/relocated Store runtime"
prefix="$scratch/relocated Store runtime"
ca="$prefix/ca.pem"
run "$prefix/bin/bundle" check
run "$prefix/bin/ruby" --disable=gems "$here/verify_macos_store_runtime.rb" "$prefix" "$architecture" default
run "$prefix/bin/bundle" exec ruby "$here/verify_macos_store_runtime.rb" "$prefix" "$architecture" bundle
# Exclusive creation: a competing output is preserved, not adopted/overwritten.
/bin/mkdir "$output"
/bin/cp -R "$prefix/." "$output/"
echo 'Store runtime component prepared. App integration, native CI, signing and distribution remain separate.'
