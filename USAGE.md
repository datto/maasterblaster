# Maasterblaster, for when you need machines turned up fast

Who run BarterTown?

â Later.... Two Sysadmins Enter, One Sysadmin Leaves...

### What is it?

A Python3 script which leverages a lightly modified python-libmass library for batch commissioning and deployment of machines with the maas
infrastructure.

### What can it really do?

Image both single and groups of Bare Metal servers (fleets) easily with one command

### What is this not for?

Building virtual machines on openstack or KVM (Tools like terraform an/or ansible are for that purpose.)

### Prerequisites (see installation steps below):

Linux Desktop (20.04 recommended)  
https://github.com/dandruczyk/python-libmaas (lightly modified fork of upstream to fix a bug for performance) Follow installation instructions from
README within that repo  
maasterblaster https://github.com/datto/maasterblaster  
API key from maas at http://<maas_region_controller_URI>:5240/MAAS/  
CSV file describing your machines (format detailed below)

### Installation:

```
apt-get install build-essential
```
# Checkout maasterblaster
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
maas-server: maas.example.net
maas-proto: https
maas-port: 443
rundeck-api-key: <PERSONAL_RUNDECK_API_KEY>
rundeck-clear-puppet-key-jobid: <RUNDECK_JOBID_TO_CLEAR_PUPPET_KEY>
rundeck-clear-salt-key-jobid: <RUNDECK_JOBID_TO_CLEAN_SALT_KEY>
foreman-user: <FOREMAN_USER>
foreman-server: puppet.example.net
parallelism: 5
```
If using foreman pairing run
```
read -s -p "Foreman Password: " FOREMAN_PASS ; export FOREMAN_PASS
```

Create a CSV describing your machines, there's a template.csv in maasterblaster/csvs to get you started
If you need to create a custom machine profile you can copy and alter one in config/config.yml.d/99_machine_profiles/. Make sure you have the
filename match the title key at the top of the file to minimize confusion.


