#!/bin/bash

if [ $# -eq 2 ]; 
then
    path=$1
    str=$2
    #echo "[Debug]: ${path} | ${str}"
    
    if [ -d "$path" ]; then
        # echo "success: ${path} found!"
        x=$(find $path -type f | wc -l)
        files=$(find $path -type f)
        y=$(grep $str $files| wc -l)
        echo "The number of files are ${x} and the number of matching lines are ${y}"

    else
        echo "Folder not found"
        exit 1
    fi
    
else
    echo "not correct arg ${$#}"
    exit 1
fi