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
HEFESTO_INCLUDES_HOME="/usr/local/share/hefesto/include"; export HEFESTO_INCLUDES_HOME
HEFESTO_MODULES_HOME="/usr/local/share/hefesto/module"; export HEFESTO_MODULES_HOME
sudo chown -R $USER /usr/local/share/hefesto
cd ../..
rm -rf hefesto
