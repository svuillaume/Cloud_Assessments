#!/bin/sh

set -eu

CONTAINER="rca"
SOURCE="server.js"
DEST="/app/server.js"

docker cp "$SOURCE" "$CONTAINER:$DEST"
docker restart "$CONTAINER"
