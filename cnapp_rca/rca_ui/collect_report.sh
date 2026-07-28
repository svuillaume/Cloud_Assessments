#!/bin/bash
set -e

docker cp rca:/app/contacts.csv ./contacts.csv

echo "Reports collected:"
ls -lh ./contacts.csv
