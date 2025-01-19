#!/usr/bin/bash

#
#                                Copyright (C) 2025 by Rafael Santiago
#
# This is a free software. You can redistribute it and/or modify under
# the terms of the GNU General Public License version 2.
#
#

git clone https://github.com/rafael-santiago/hefesto --recursive
cd hefesto/src
printf "\n" > blau.txt
sudo ./build.sh < blau.txt
echo "HEFESTO_INCLUDES_HOME=/usr/local/share/hefesto/include" >> "$GITHUB_ENV"
echo "HEFESTO_MODULES_HOME=/usr/local/share/hefesto/module" >> "$GITHUB_ENV"
sudo chown -R $USER /usr/local/share/hefesto
cd ../..
rm -rf hefesto
