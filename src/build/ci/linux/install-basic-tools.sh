#!/usr/bin/bash

#
#                              Copyright (C) 2025 by Rafael Santiago
#
# This is free software. You can redistribute it and or/modify under
# the terms of the GNU General Public License version 2.
#
#


deps_file=$(dirname $0)/deps.txt

sudo apt-get update

for dep in `cat $deps_file`
do
    sudo apt-get install -y $dep
done
