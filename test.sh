#!/bin/bash

FILES=(tests/test1.pdf tests/test2.txt tests/Nessus.deb)

echo "--- SHA256 Test ---"
for file in "${FILES[@]}"; do
    start=$(date +%s.%N)
    hash=$(python3 sha256.py -f "$file")
    end=$(date +%s.%N)
    time_taken=$(echo "$end $start" | awk '{print $1-$2}')
    # Compare the hashes using sha256sum which is command line utility
    sha256=$(sha256sum "$file" | awk '{print $1}')
    if [ "$hash" == "$sha256" ]; then
        echo -e "Passed: $file  Time taken: $time_taken seconds"
    else
        echo "Failed: $file"
    fi
done
echo -e "-------------------\n"

echo "--- MD5 Test ---"
for file in "${FILES[@]}"; do
    start=$(date +%s.%N)
    hash=$(python3 md5.py -f "$file")
    end=$(date +%s.%N)
    time_taken=$(echo "$end $start" | awk '{print $1-$2}')
    # Compare the hashes using md5sum which is command line utility
    sha256=$(md5sum "$file" | awk '{print $1}')
    if [ "$hash" == "$sha256" ]; then
        echo -e "Passed: $file  Time taken: $time_taken seconds"
    else
        echo "Failed: $file"
    fi
done
echo "----------------"
