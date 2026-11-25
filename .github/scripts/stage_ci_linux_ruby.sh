#!/usr/bin/env bash
set -euo pipefail

# Copy only the Ruby selected by the pinned setup action. The hosted tool
# cache can carry inherited ACLs. The input and the verifier's ACL policy
# stay intact, and the independently admitted copy has its own metadata.
original=/opt/hostedtoolcache/Ruby/3.3.12/x64
[[ "$EUID" == 0 && "$#" -gt 0 && "$1" == /* && "$2" == -I && "$3" == -B ]]
[[ "$(/usr/bin/realpath -- "$original/bin/ruby")" == "$original/bin/ruby" ]]
[[ -x /usr/bin/rsync && -x /usr/bin/unshare ]]

parent="$(/usr/bin/mktemp -d /opt/mrk-ci-ruby.XXXXXXXX)"
[[ "$parent" =~ ^/opt/mrk-ci-ruby\.[a-zA-Z0-9]{8}$ ]]
runtime="$parent/runtime"
/usr/bin/install -d -m 0755 -o root -g root -- "$runtime"
/usr/bin/rsync -rltp --safe-links --chown=0:0 --chmod=Du=rwx,Dgo=rx,Fu+rw,Fgo-w \
  -- "$original/" "$runtime/"
# Require the full byte, file-type and symlink roster. This also refuses a
# copied tree missing an external symlink that --safe-links withheld.
changes="$(/usr/bin/rsync -rlcn --delete --itemize-changes -- "$original/" "$runtime/")"
[[ -z "$changes" ]]

# The upstream Ruby is built for the original absolute prefix. Expose the
# audited copy there in this verifier's private mount namespace only.
exec /usr/bin/unshare --mount --propagation private /bin/bash -euo pipefail -c '
  copy=$1
  prefix=$2
  shift 2
  /usr/bin/mount --bind -- "$copy" "$prefix"
  [[ "$(/usr/bin/stat -c %d:%i -- "$prefix")" == "$(/usr/bin/stat -c %d:%i -- "$copy")" ]]
  exec "$@"
' mrk-ci-ruby "$runtime" "$original" "$@"
