#! /bin/sh
# This script is called by the changeset action in release.yml.
#
# `npm publish` moves the `latest` dist-tag to whatever it publishes. A hotfix from a
# maintenance branch such as `v0` must not do that once a newer major is out, so when
# npm's `latest` is already ahead of this package's major, publish under `v<major>`.

set -e

name=$(node -p "require('./package.json').name")
major=$(node -p "require('./package.json').version.split('.')[0]")
latest_major=$(npm view "$name" dist-tags.latest | cut -d. -f1)

if [ -z "$latest_major" ]; then
  echo "Could not read the latest dist-tag for $name from npm; refusing to publish blind." >&2
  exit 1
fi

if [ "$major" -lt "$latest_major" ]; then
  echo "npm latest is ${latest_major}.x and this is ${major}.x: publishing under the v${major} dist-tag."
  exec npx changeset publish --tag "v$major"
fi

exec npx changeset publish
