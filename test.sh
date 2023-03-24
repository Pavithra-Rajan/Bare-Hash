#!/bin/bash

FILES=(tests/test1.pdf tests/test2.txt tests/Nessus.deb)

for file in "${FILES[@]}"
do
    start=$(date +%s.%N)
    hash=$(python3 sha256.py -f "$file")
    end=$(date +%s.%N)
    time_taken=$(echo "$end - $start" | bc)
    # Compare the hashes using sha256sum which is command line utility
    sha256=$(sha256sum "$file" | awk '{print $1}')
    if [ "$hash" == "$sha256" ]
    then
        echo "Passed: $file Time taken: $time_taken seconds"
    else
        echo "Failed: $file"
    fi
done
