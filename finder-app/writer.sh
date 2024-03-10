#!/bin/bash

if [ $# -eq 2 ]; 
then
    full_path=$1
    str=$2

    dir_path=$(dirname ${full_path})
    base_name=$(basename ${full_path})

    #echo "[Debug]: ${path} | ${str}"
    mkdir -p $dir_path

    if [ -d "$dir_path" ]; then
        # echo "success: ${path} found!"
        echo "${str}" > $full_path

    else
        echo "Folder not found"
        exit 1
    fi
    
else
    echo "not correct arg ${$#}"
    exit 1
fi