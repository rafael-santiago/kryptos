#!/usr/bin/bash

#
#                                Copyright (C) 2025 by Rafael Santiago
#
# This is a free software. You can redistribute it and/or modify under
# the terms of the GNU General Public License version 2.
#
#

ftp ftp://ftp.netbsd.org/pub/pkgsrc/current/pkgsrc.tar.gz
sudo tar -xzf pkgsrc.tar.gz -C /usr
PKG_PATH="http://ftp.NetBSD.org/pub/pkgsrc/packages/$(uname -s)/$(uname -m)/$(uname -r | cut -f '1 2' -d.)/All"
export PATH PKG_PATH
