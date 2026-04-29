#!/bin/bash
set -e

docker cp rca:/app/rca.html ./rca.html
docker cp rca:/app/rca.pdf  ./rca.pdf

echo "Reports collected:"
ls -lh ./rca.html ./rca.pdf
