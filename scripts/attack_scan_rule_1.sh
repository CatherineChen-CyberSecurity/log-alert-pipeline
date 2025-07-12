#!/bin/bash

# This script runs an Nmap aggressive scan against a target IP
# in an infinite loop, with a 10-second delay between each scan.
#
# To stop the script, press Ctrl+C.

TARGET="172.21.0.10"
DELAY=10

echo "Starting continuous Nmap scan against $TARGET."
echo "There will be a $DELAY second delay between each scan."
echo "Press Ctrl+C to stop."
echo "----------------------------------------"

# Infinite loop
while true
do
    echo "[$(date)] Executing nmap -A $TARGET..."
    nmap -A $TARGET

    echo "----------------------------------------"
    echo "Scan complete. Waiting for $DELAY seconds..."
    sleep $DELAY
done