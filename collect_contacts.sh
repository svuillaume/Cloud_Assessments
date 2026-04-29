#!/bin/sh
echo "Fetching Contacts"
sleep 1
sudo docker cp rca:/app/contacts.csv ./contacts.csv
sleep 1
echo "Here is the list of contacts:"
cat contacts.csv
