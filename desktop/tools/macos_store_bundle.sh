#!/bin/sh
# Private packaged Bundler entry. The shared core invokes only exec ruby/check.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
unset RUBYOPT RUBYLIB GEMRC
export GEM_HOME="$root/lib/ruby/gems/3.3.0" GEM_PATH="$root/lib/ruby/gems/3.3.0"
export BUNDLE_IGNORE_CONFIG=1 BUNDLE_FROZEN=true BUNDLE_AUTO_INSTALL=false
export BUNDLE_GEMFILE="$root/tooling/Gemfile" BUNDLE_PATH="$root/bundle"
export BUNDLE_FORCE_RUBY_PLATFORM=true SSL_CERT_FILE="$root/ca.pem"
if [ "${1-}" = exec ]; then
    shift
    if [ "${1-}" != ruby ]; then
        echo 'The packaged Store runtime supports bundle exec ruby only.' >&2
        exit 64
    fi
    shift
    # Separate Ruby argv preserves spaces in the installed path. The ordinary
    # script, $PROGRAM_NAME, ARGV and exit handling remain Ruby's own, not load().
    exec "$root/bin/ruby" -r "$root/bin/mrk_bundle_setup.rb" "$@"
fi
exec "$root/bin/ruby" "$GEM_HOME/gems/bundler-4.0.16/exe/bundle" "$@"
