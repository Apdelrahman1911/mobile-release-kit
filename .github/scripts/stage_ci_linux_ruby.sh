#!/usr/bin/env bash
set -euo pipefail

# Copy only the Ruby selected by the pinned setup action. The hosted tool
# cache can carry inherited ACLs. The input and the verifier's ACL policy
# stay intact, and the independently admitted copy has its own metadata.
original=/opt/hostedtoolcache/Ruby/3.3.12/x64
[[ "$(command -v ruby)" == "$original/bin/ruby" ]]
[[ "$(/usr/bin/realpath -- "$original/bin/ruby")" == "$original/bin/ruby" ]]
[[ -x /usr/bin/rsync && -x /usr/bin/sudo ]]

parent="$(/usr/bin/sudo -n /usr/bin/mktemp -d /opt/mrk-ci-ruby.XXXXXXXX)"
[[ "$parent" =~ ^/opt/mrk-ci-ruby\.[a-zA-Z0-9]{8}$ ]]
runtime="$parent/runtime"
/usr/bin/sudo -n /usr/bin/install -d -m 0755 -o root -g root -- "$runtime"
/usr/bin/sudo -n /usr/bin/rsync -rltp --safe-links --chown=0:0 --chmod=Du=rwx,Dgo=rx,Fu+rw,Fgo-w \
  -- "$original/" "$runtime/"
# Require the full byte, file-type and symlink roster. This also refuses a
# copied tree missing an external symlink that --safe-links withheld.
changes="$(/usr/bin/sudo -n /usr/bin/rsync -rlcn --delete --itemize-changes -- "$original/" "$runtime/")"
[[ -z "$changes" ]]
/usr/bin/sudo -n /usr/bin/chmod 0755 -- "$parent"

/usr/bin/env -i PATH=/usr/bin:/bin "$runtime/bin/ruby" --disable-gems -rrbconfig -rfiddle -e '
  root, original = ARGV
  abort "Ruby provider version or prefix differs" unless RUBY_VERSION == "3.3.12" && RbConfig::TOPDIR == root && RbConfig.ruby == root + "/bin/ruby"
  abort "Ruby is using its original tool cache" if File.read("/proc/self/maps").include?(original + "/") ||
    ($LOAD_PATH + $LOADED_FEATURES).any? { |path| path.start_with?(original + "/") }
' "$runtime" "$original"
printf '%s\n' "$runtime/bin/ruby"
