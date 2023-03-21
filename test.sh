#!/bin/bash

FILES=(tests/test1.pdf tests/test2.txt)

for file in "${FILES[@]}"
do
    hash=$(python3 sha256.py -f "$file")

    # Compare the hashes using sha256sum which is command line utility
    sha256=$(sha256sum "$file" | awk '{print $1}')
    if [ "$hash" == "$sha256" ]
    then
        echo "Passed: $file"
    else
        echo "Failed: $file"
    fi
done
