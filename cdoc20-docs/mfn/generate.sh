#!/bin/sh

if ! [ -x "$(command -v jekyll)" ]; then
    echo "jekyll must be installed!"
    exit
fi

jekyll b -s jekyll -d jekyll/_site && mv jekyll/_site/index.html ./MFN.md
