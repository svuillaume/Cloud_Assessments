#!/bin/sh
docker cp rca:/app/contacts.csv ./contacts.csv
cat contacts.csv
