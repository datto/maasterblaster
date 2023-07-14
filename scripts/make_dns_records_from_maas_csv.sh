#!/bin/bash

## This file is part of Maasterblaster.
 #
 # Copyright Datto, Inc.
 # Author: David Andruczyk <dandruczyk@datto.com>
 #
 # Licensed under the GNU General Public License Version 3
 # Fedora-License-Identifier: GPLv3+
 # SPDX-2.0-License-Identifier: GPL-3.0+
 # SPDX-3.0-License-Identifier: GPL-3.0-or-later
 #
 # Maasterblaster is free software: you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
 # the Free Software Foundation, either version 3 of the License, or
 # (at your option) any later version.
 #
 # Maasterblaster is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 # GNU General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License
 # along with Maasterblaster.  If not, see <https://www.gnu.org/licenses/>.
 #

# This is a rudimentary script template forgenerating nsupdate ccompatible
# output suitable for direct copy/paste to create DNS records in your local
# Active directory DNS environment.  

# Forward and reverse records are created:
# CAVEAT:  The FIRST ip in the netcfg (last field) is used as the primary IP for the host
# any other ip's for vlan or bridge interfaces don't get records.
#
# This script qill require modification before first use to suit your environment


AD_DNS_SERV="YOUR_DNS_SERVER_IP"
IPMI_DOMAIN="ipmi.example.com"
HOST_DOMAIN="example.com"

if ! test -f ${1} ; then 
  echo "Need path to CSV file to maasterblaster CSV file to parse" 
  exit -1
fi

cat << HEADER
# Setup DNS records
# Copy and paste between the "=" signs
# ==========================================
HEADER
echo "nsupdate -g << EOT"
echo "server ${AD_DNS_SERV}"
#Generate IPMI DNS records for maasterblaster CSV file
#FWD's
cat ${1} |grep -v ^$ | sed -e '1,1d' | awk -F , -v domain=${IPMI_DOMAIN} '{print "update add "$1"."$domain". 3600 A "$8}'
echo "send"
#REV's
cat ${1} |grep -v ^$ | sed -e '1,1d' | awk -F , -v domain=${IPMI_DOMAIN} '{split($8, a, "."); print "update add "a[4]"."a[3]"."a[2]"."a[1]".in-addr.arpa. 3600 PTR "$1"."$domain"."}'
echo "send"

#Generate host DNS records for maasterblaster CSV file  Assume's primary address is first one in netcfg section
#FWD's
cat ${1} |grep -v ^$ | sed -e '1,1d' | awk -F , '{split($9, a, " "); split(a[1], b, ":"); print "update add "$1"."$2". 3600 A "b[2]}'
echo "send"
#REV's
cat ${1} |grep -v ^$ | sed -e '1,1d' | awk -F , '{split($9, a, " "); split(a[1], b, ":"); split(b[2], c, "."); print "update add "c[4]"."c[3]"."c[2]"."c[1]".in-addr.arpa. 3600 PTR "$1"."$2"."}'
echo "send"
echo "quit"
echo "EOT"
echo "# =========================================="

