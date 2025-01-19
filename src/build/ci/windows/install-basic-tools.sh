#!/usr/bin/bash

#
#                              Copyright (C) 2025 by Rafael Santiago
#
# This is free software. You can redistribute it and or/modify under
# the terms of the GNU General Public License version 2.
#
#

deps_file=$(dirname $0)/deps.txt

pacman -Sy --noconfirm git dos2unix
git ls-files -z | xargs -0 dos2unix

pacman -Q > .PACKSWHO

pkg2install=""

input=$deps_file

while IFS= read -r dep
do
    if [[ `echo $dep | grep ^# | wc -l` == 1 ]] ; then
        continue
    fi
    if [[ `cat .PACKSWHO | grep "^$dep " | wc -l` != 1 ]] ; then
        pkg2install=$pkg2install" $dep"
        echo "info: $dep will be installed."
    else
        echo "info: $dep is already installed."
    fi
done < "$input"

if [[ ! -z $pkg2install ]] ; then
    pacman -Sy $pkg2install --needed --noconfirm >&2
fi

rm -f .PACKSWHO > /dev/null 2>&1
