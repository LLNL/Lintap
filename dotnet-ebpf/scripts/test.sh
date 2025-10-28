#!/bin/bash

echo "Generating test openat() events..."
echo "Run this in a separate terminal while the tracer is running"
echo

for i in {1..5}; do
    echo "Test iteration $i"
    
    # These commands will trigger openat calls
    ls /tmp > /dev/null 2>&1
    cat /etc/hostname > /dev/null 2>&1
    stat /proc/cpuinfo > /dev/null 2>&1
    
    sleep 1
done

echo
echo "Test complete! Check the tracer output for these events."
