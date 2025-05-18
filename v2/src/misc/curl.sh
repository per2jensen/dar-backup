#!/usr/bin/env bash

#  clones
curl -L \
  -H "Accept: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/per2jensen/dar-backup/traffic/clones

