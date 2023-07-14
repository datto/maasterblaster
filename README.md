
# Who run Bartertown?

##     Two Sysadmins Enter, One Sysadmin leaves....


Welcome to MaaSterblaster a tool designed for rapid deployment of 
bare metal machines anywhere where Canonical's MaaS has a presence. 

Prerequisites:
 - Ubuntu Desktop (tested on 18.04 and 20.04)
 - https://github.com/dandruczyk/python-libmaas  (lightly modified fork of upstream to fix a bug for performance) Follow installation instructions from README within that repo
 - python3
 - API Key from MAAS
 - CSV file describing your machines

### Input CSV
**NOTE: The input CSV must have a header**
`shortname,domain,machine_profile,macs,power,poweruser,powerpass,powerip,netcfg,foreman_hostgroup_id

Fields:
 - shortname            Short hostname for the host (use1-foobar-1)
 - domain               Domain name (example.lan, example.com, example.net, etc)
 - machine_profile      See below
 - macs                 Space separated list of MAC addresses for the host (1 min)
 - power                ipmi until we use hardware with redfish or other OOB mgmt
 - poweruer             IPMI username
 - powerpass            IPMI password
 - powerip              IPMI IP
 - netcfg               See below for this structure
 - foreman_hostgroup_id The numerical ID of the hostgroup to pre-create this host in

### Caveats
Maasterblaster uses PXE to boot and image machines, thus each subnet that is 
currently MAAS capable has a pool set aside for this purpose, thus the number
of machines per subnet that can be commssioned, deployed or put into rescue 
mode at any one time is limited to the size of the DHCP pool allocated to MAAS
within that subnet (see the subnets tab in the GUI).  It's recommended to limit
the number of simultaneous commissions/deploys in any one subnet to 10 at a
time. 

### Machine Profiles
These refer to a stanza within config.yml which gives maasterblaster guidance
on how to configure disk and network layouts.  This yaml file uses anchors
and aliases. Anchors define a chunk of configuration,  aliases are used to
refer to it elsewhere, it's a way to reduce repetition.

  Anchors are marked with a `&anchorname`  
  Plain aliases (no overrides) are just `*anchorname`  
  Aliases  that allow overrides are `<<: *anchorname`  
see https://yaml.org/spec/1.2/spec.html#id2765878

See the USAGE.md page for details on machine profiles and usage

### Setup
```
cd ~/git ; git clone https://github.com/datto/maasterblaster.git
cd maasterblaster
pipenv shell
pipenv install
```
Setup ~/.config/maasterblaster.conf
```
      ---
      maas-api-key: "<PERSONAL_MAAS_API_KEY>"
      maas-server: maas.example.com
      maas-proto: https
      maas-port: 443
      rundeck-api-key: <PERSONAL_RUNDECK_API_KEY>
      rundeck-clear-puppet-key-jobid: <RUNDECK_KEY_TO_CLEAR_PUPPET_KEY>
      rundeck-clear-salt-key-jobid: <RUNDECK_KEY_TO_CLEAR_SALT_KEY>
      foreman-user: <FOREMAN_USER>
      foreman-server: puppet.example.com
      parallelism: 5

```
You may wish to set the following params in maasterblaster.py to suit your environment:
```
DEFAULT_MAAS_SERVER = "maas.example.com"
DEFAULT_RUNDECK_SERVER = "rundeck.example.com"
DEFAULT_FOREMAN_SERVER = "puppet.example.com"
```

These will just set the defaults so you won't need to put them into a config file (above) or on the command line

If using foreman pairing set the foreman password associated with your account
`read -s -p "Foreman Password: " FOREMAN_PASS ; export FOREMAN_PASS`

To commission and deploy nodes in your CSV file:
`./maasterblaster -d DEBUG -i /path/to/csv -C -D`

# License
Licensed under the GNU General Public License Version 3  
Copyright Datto, Inc.  
Authored by David Andruczyk
