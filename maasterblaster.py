#!/usr/bin/env python3

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
##

""" MaasterBlaster tries to provide a way to build machines en-mass with MaaS """

import configargparse
import asyncio
import base64
import calendar
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import copy
import csv
import json
import ipaddress
import time
import logging
import os
import pprint
import re
import requests
import string
import sys
import time
import traceback
import typing
import yaml
import maas.client
from maas.client.enum import NodeStatus
from maas.client.enum import InterfaceType
from maas.client.enum import PowerState
from maas.client.utils.maas_async import asynchronous
from typing import Tuple



BLOCK_SIZE = 4*1024**2 # 4 Meg
# Maas Seems to have a size related error for MD/LVM
# volumes, this ia fudge factor to spare a little space to get around the bug

DISK_FUDGE = 1.0/3000.0
CONFIGFILE = "config.yml"
LOGGER = logging.getLogger('maasterblaster')
DEFAULT_MAAS_SERVER = "maas.example.com"
DEFAULT_RUNDECK_SERVER = "rundeck.example.com"
DEFAULT_FOREMAN_SERVER = "puppet.example.com"
BOND_PREFIX = "96:EF:8F"

PP = pprint.PrettyPrinter(indent=4)
MD_COUNT = {}
ESP_COUNT = {}

# Classes: (custom foreman client class)
class ForemanClient:
    """ Foreman API orchestrator class """


    def __init__(self, args):
        self.config = args
        self.foreman_user = self.config.foreman_user
        self.foreman_pass = self.config.foreman_pass
        if not self.foreman_user:
            LOGGER.critical("Foreman user is unset, cannot continue")
            exit(1)
        if not self.foreman_pass:
            LOGGER.critical("Foreman password is unset, cannot continue")
            exit(1)
        self.foreman_api_url = "https://" + self.config.foreman_server + "/api/"
        self.headers = {
            "Authorization": "Basic {}".format(
                base64.b64encode(
                    "{user}:{pw}".format(user=self.foreman_user,
                                         pw=self.foreman_pass).encode("ascii")
                ).decode()
            )
        }

    def _request(self, method, url, params=None, data=None, additional_headers=None):
        """Templated function that orchestrates the requests being made to the
        Foreman API"""
        # pylint: disable-msg=too-many-arguments
        headers = self.headers
        if additional_headers:
            headers.update(additional_headers)

        kwargs = {"headers": headers}
        if params:
            kwargs["params"] = params
        if data:
            kwargs["data"] = data

        response = requests.request(method, url, **kwargs)
        LOGGER.info(method+ " " + url)

        return response

    def _get_arch(self, architecture="x86_64"):
        """
        Retrieve the architecture of the host. Example:
        Search result:
        {
            "total": 3,
            "subtotal": 1,
            "page": 1,
            "per_page": 50,
            "search": "name = x86_64",
            "sort": {
                "by": null,
                "order": null
            },
            "results": [{"created_at":"2017-06-22T22:10:11.000Z","updated_at":"2017-06-22T22:10:11.000Z","name":"x86_64","id":1}]
        }
        """
        method = "GET"
        url = self.foreman_api_url + "architectures"
        search_param = "name = {}".format(architecture)
        params = {"search": search_param}
        response = self._request(method, url, params)
        search_results = response.json()
        found_architectures = search_results["results"]
        if not found_architectures:
            raise Exception("Architecture " + architecture + " not found")
        if len(found_architectures) > 1:
            raise Exception("Multiple architectures found for " + architecture)
        return found_architectures[0]

    def _get_os(self, operatingsystem="Ubuntu 18.04 LTS"):
        """
        Retrieve the OS of the host. Example:

        Search result:
        {
            "total": 12,
            "subtotal": 1,
            "page": 1,
            "per_page": 50,
            "search": "name = Ubuntu 18.04 LTS",
            "sort": {
                "by": null,
                "order": null
            },
            "results": [{"description":"Ubuntu 18.04 LTS","major":"18","minor":"04","family":"Debian","release_name":"bionic","password_hash":"SHA256","created_at":"2018-05-10T21:08:04.000Z","updated_at":"2018-05-10T21:08:04.000Z","id":4,"name":"Ubuntu","title":"Ubuntu 18.04 LTS"}]
        }
        """
        method = "GET"
        url = self.foreman_api_url + "operatingsystems"
        search_param = "name = {}".format(operatingsystem)
        params = {"search": search_param}
        response = self._request(method, url, params)
        search_results = response.json()
        found_oses = search_results["results"]
        if not found_oses:
            raise Exception("OS " + operatingsystem + " not found")
        if len(found_oses) > 1:
            raise Exception("Multiple OS types found for " + operatingsystem)
        return found_oses[0]

    def get_host(self, fqdn="somehost.example.com"):
        """
        Search result:
        {
            "total": 9805,
            "subtotal": 1,
            "page": 1,
            "per_page": 50,
            "search": "name = somehost.example.com",
            "sort": {
                "by": null,
                "order": null
            },
            "results": [{"ip":null,"ip6":null,"environment_id":1,"environment_name":"example_environment","last_report":null,"mac":"00:00:00:00:00:00","realm_id":null,"realm_name":null,"sp_mac":null,"sp_ip":null,"sp_name":null,"domain_id":1,"domain_name":"somehost.example.com","architecture_id":1,"architecture_name":"x86_64","operatingsystem_id":4,"operatingsystem_name":"Ubuntu 18.04 LTS","subnet_id":null,"subnet_name":null,"subnet6_id":null,"subnet6_name":null,"sp_subnet_id":null,"ptable_id":null,"ptable_name":null,"medium_id":null,"medium_name":null,"pxe_loader":"PXELinux BIOS","build":false,"comment":null,"disk":null,"installed_at":null,"model_id":null,"hostgroup_id":1,"owner_id":1,"owner_type":"User","enabled":true,"managed":true,"use_image":null,"image_file":"","uuid":null,"compute_resource_id":null,"compute_resource_name":null,"compute_profile_id":null,"compute_profile_name":null,"capabilities":["build"],"provision_method":"build","certname":"somehost.example.com","image_id":null,"image_name":null,"created_at":"2020-12-15T23:15:16.000Z","updated_at":"2020-12-15T23:15:16.000Z","last_compile":null,"global_status":0,"global_status_label":"OK","puppet_status":0,"model_name":null,"build_status":0,"build_status_label":"Installed","name":"somehost.example.com","id":14231,"puppet_proxy_id":null,"puppet_proxy_name":null,"puppet_ca_proxy_id":null,"puppet_ca_proxy_name":null,"puppet_proxy":null,"puppet_ca_proxy":null,"hostgroup_name":"example","hostgroup_title":"example_namespace/example"}]
        }
        """
        method = "GET"
        url = self.foreman_api_url + "hosts"
        search_param = "name = {}".format(fqdn)
        params = {"search": search_param}
        response = self._request(method, url, params)
        search_results = response.json()
        found_hosts = search_results["results"]
        if not found_hosts:
            LOGGER.warning("Host %s not found", fqdn)
            return None, False
        if len(found_hosts) > 1:
            raise Exception("Multiple hosts found for " + fqdn)
        return found_hosts[0], True

    def delete_host(self, fqdn):
        """ Delete the host in forman """
        LOGGER.debug("delete_host FQDN: %s", fqdn)
        host_data, result = self.get_host(fqdn)
        method = "DELETE"
        host_id = str(host_data['id'])
        url = self.foreman_api_url + "hosts" + "/" + host_id
        try_count = 0

        response = self._request(
            method, url
        )
        if response.ok:
            return json.loads(response.text)
        else:
            LOGGER.debug("Error deleting host: %s", response.text)
            LOGGER.debug("Failed to delete Host.\n")


    def pair_host(self, fqdn, hostgroup_id):
        """ Pair the host in foreman """
        LOGGER.debug("FQDN %s. hostgroup_id %s", fqdn, hostgroup_id)
        # pylint: disable-msg=no-else-return
        arch = self._get_arch()
        arch_id = arch["id"]
        operatingsystem = self._get_os()
        os_id = operatingsystem["id"]
        method = "POST"
        data = {
            "host": {
                "name": fqdn,
                "mac": "00:00:00:00:00:00",
                "architecture_id": arch_id,
                "operatingsystem_id": os_id,
                "hostgroup_id": hostgroup_id,
                "build": "false",
                "compute_attributes": {"volumes_attributes": {}},
                "managed": "true",
                "enabled": "true",
                "overwrite": "true",
                "interfaces_attributes": [],
            }
        }
        data = json.dumps(data)
        url = self.foreman_api_url + "hosts"
        try_count = 0

        response = self._request(
            method, url, data=data, additional_headers={"Content-Type": "application/json"}
        )
        if response.ok:
            return json.loads(response.text)
        else:
            LOGGER.debug("Error creating host %s", response.text)
            LOGGER.debug("Failed to create Host.\n")


    def update_host_hostgroup(self, fqdn, hostgroup_id):
        """Pair the host in foreman """
        LOGGER.debug("fqdn %s. hostgroup_id %s", fqdn, hostgroup_id)
        # pylint: disable-msg=no-else-return
        host_data, result = self.get_host(fqdn)
        method = "PUT"
        data = {
            "host": {
                "hostgroup_id": hostgroup_id,
            }
        }
        host_id = str(host_data['id'])
        data = json.dumps(data)
        url = self.foreman_api_url + "hosts" + "/" + host_id
        try_count = 0

        response = self._request(
            method, url, data=data, additional_headers={"Content-Type": "application/json"}
        )
        if response.ok:
            return json.loads(response.text)
        else:
            LOGGER.debug("Error updating host hostgroup %s", response.text)
            LOGGER.debug("Failed to update Host.\n")


# Functions:

def LINE() -> str:
    """ Print the line number for debugging """
    return sys._getframe(1).f_lineno

class ThreadPoolExecutorStackTraced(ThreadPoolExecutor):

    def submit(self, fn, *args, **kwargs):
        """Submits the wrapped function instead of `fn`"""

        return super(ThreadPoolExecutorStackTraced, self).submit(
            self._function_wrapper, fn, *args, **kwargs)

    def _function_wrapper(self, fn, *args, **kwargs):
        """Wraps `fn` in order to preserve the traceback of any kind of
        raised exception

        """
        try:
            return fn(*args, **kwargs)
        except Exception:
            raise sys.exc_info()[0](traceback.format_exc())  # Creates an
                                                             # exception of the
                                                             # same type with the
                                                             # traceback as
                                                             # message


def build_user_data(host_config: dict) -> str:
    """ Spits out a bas64 endoded version of the user_data section """
    user_data = {}

    if 'user_data' in host_config:
        user_data = host_config['user_data']

    user_data = b"#cloud-config\n" + yaml.dump(user_data).encode("utf-8")
    return user_data


def setup_logger(args: dict) -> None:
    """ Sets up the logger with seemingly sane defaults """
    LOGGER.setLevel(args.debug_level)
    # Setup handling output to the console at lowest level
    log_to_console = logging.StreamHandler()
    log_to_console.setLevel(logging.DEBUG)
    #
    # Default format
    #
    if args.timestamp:
        formatter = logging.Formatter("%(asctime)s - %(levelname).4s - %(message)s")
    else:
        formatter = logging.Formatter("%(levelname)s = %(message)s")
    #
    # Set the console output format
    #
    log_to_console.setFormatter(formatter)

    #
    # If the --logfile param is specified, check if target is writable and
    # if so, start logging to it, it not error out
    #
    try:
        if args.logfile:
            log_to_file = logging.FileHandler(args.logfile)
            log_to_file.setLevel(logging.DEBUG)
            log_to_file.setFormatter(formatter)
            LOGGER.addHandler(log_to_file)
            if args.debug_level != "NOTSET":
                LOGGER.info("Startup")
        else:
            LOGGER.addHandler(log_to_console)
            if args.debug_level != "NOTSET":
                LOGGER.info("Startup")
    except IOError as err:
        LOGGER.critical("Error trying to open %s, error(%i): %s",
                        args.logfile,
                        err.errno,
                        err.strerror)

def load_csv(config: dict, file: str, limit: list) -> list:
    """ Parses Input CSV, validates for blank fields, the stores into an array of
    dictionaries for future use """
    csvfile = open(file, newline='')
    csvreader = csv.DictReader(
        filter(lambda row: row[0] != '#', csvfile),
        dialect="unix",
        delimiter=",",
        quotechar='"')
    hosts = []
    # Validate that the fields aren't blank
    for row in csvreader:
        # Input Validation
        # shortname Required
        # domain    Required
        # profile   Required
        # macs      Required
        # power     Required
        # poweruser Required
        # powerpass Required
        # powerip   Required
        # netcfg    Required
        # foreman_hostgroup_id Optional
        assert(row['shortname']),\
               "Shortname missing on row %i" % csvreader.line_num
        if limit and row['shortname'] not in limit:
            LOGGER.info("limiting in use, filtering out %s", row['shortname'])
            continue
        assert(row['domain']),\
               "Domain name missing on row %i" % csvreader.line_num
        assert(row['machine_profile']),\
               "maasterblaster machine_profile to use is missing on row" % csvreader.line_num
        assert(row['macs']),\
               "No MAC addresses present (space separated) on row " % csvreader.line_num
        assert(row['power']),\
               "Power Type not specified, expected IPMI or similar on row " % csvreader.line_num
        assert(row['poweruser']),\
               "NO Power Username specified on row" % csvreader.line_num
        assert(row['powerpass']),\
               "NO Power Password specified on row" % csvreader.line_num
        assert(row['powerip']),\
               "NO Power IP address specified on row" % csvreader.line_num
        assert(row['netcfg']),\
               "NO Networking configuration present on row" % csvreader.line_num
        if 'foreman_hostgroup_id' not in row:
            LOGGER.info("NO foreman_hostgroup_id configuration present on row")
#        assert(row['foreman_hostgroup_id']),\
#               "NO Foreman_hostgroup_id configuration present on row" % csvreader.line_num
        # If we got here, basic validation passed
        hosts.append(row)
    return hosts


def parse_args() -> dict:
    """ Handle ye mighty arguments """
    parser = configargparse.ArgParser(
        default_config_files=["/etc/maasterblaster.conf",
                              "~/.config/maasterblaster.conf"],
        args_for_setting_config_path=['--defaults'],
        description='Two Sysadmins Enter, One Sysadmin Leaves.... '
                    'Batch machine Imager, Beta quality at best, use at your own risk!')
    group = parser.add_argument_group('MaaS options')
    group.add_argument('--maas-api-key',
                       env_var='MAAS_API_KEY',
                       help="MaaS API key to use")
    group.add_argument('--maas-proto',
                       default='https',
                       choices=['http', 'https'],
                       env_var='MAAS_PROTO',
                       help="Maas URL protocol (http, https)")
    group.add_argument('--maas-port',
                       default=443,
                       type=int,
                       env_var='MAAS_PORT',
                       help="Maas URL port (443)")
    group.add_argument('--maas-server',
                       env_var='MAAS_SERVER',
                       default=DEFAULT_MAAS_SERVER,
                       help="Maas server hostname")
    group.add_argument('--rundeck-server',
                       env_var="RUNDECK_SERVER",
                       default=DEFAULT_RUNDECK_SERVER,
                       help="rundeck server hostname")
    group.add_argument('--rundeck-api-key',
                       env_var="RUNDECK_API_KEY",
                       help="rundeck api key")
    group.add_argument('--rundeck-clear-puppet-key-jobid',
                       env_var="RUNDECK_CLEAR_PUPPET_KEY_JOB_ID",
                       help="rundeck clear puppet key job id")
    group.add_argument('--rundeck-clear-salt-key-jobid',
                       env_var="RUNDECK_CLEAR_SALT_KEY_JOB_ID",
                       help="rundeck clear salt key job id")
    group.add_argument('--foreman-server',
                       env_var='FOREMAN_SERVER',
                       default=DEFAULT_FOREMAN_SERVER,
                       help="foreman server hostname")
    group.add_argument('--foreman-user',
                       env_var='FOREMAN_USER',
                       help="foreman user")
    group.add_argument('--foreman-pass',
                       env_var='FOREMAN_PASS',
                       help="foreman password")
    group = parser.add_argument_group('Debugging')
    group.add_argument('-l', '--logfile',
                       help='path to log file to use, otherwise errors come out the console')
    group.add_argument('--timestamp', action='store_true',
                       help='Use timestamped logs')
    group.add_argument('-d', '--debug-level',
                       default='NOTSET',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                       help='Debug Level')
    group = parser.add_argument_group('Configuration')
    parser.add_argument('--internal-config', default='config.yml',
                        help='path to config file to use')
    group.add_argument('-i', '--input-csv',
                       help='Input CSV')
    lockgroup = parser.add_argument_group('Locking')
    lockgroup.add_argument('-L',
                           '--lock',
                           action='store_true',
                           help='Lock machine to prevent modification')
    lockgroup.add_argument('-U',
                           '--unlock',
                           action='store_true',
                           help='Unlock machines requires --force')
    cd_group = group.add_argument_group('Commissioning and Deployment')
    cd_group.add_argument('-C',
                          '--commission',
                          action='store_true',
                          help='Commission machines')
    cd_group.add_argument('-D',
                          '--deploy',
                          action='store_true',
                          help='Deploy machines')
    group.add_argument('-R',
                       '--release',
                       action='store_true',
                       help='Release machines requires --force to be set')
    group.add_argument('-A',
                       '--abort',
                       action='store_true',
                       help='Abort machines requires --force to be set')
    group.add_argument('--delete',
                       action='store_true',
                       help='Delete machines requires --force to be set')
    parser.add_argument('--force',
                        action='store_true',
                        help='force (to override prompts)')
    parser.add_argument('--skip-custom',
                        env_var='MAAS_SKIP_CUSTOM',
                        action='store_true',
                        help='Skips the custom commission firmware upgrade of'
                             ' sas controller and the array drive smart tests')
    parser.add_argument('-P', '--parallelism',
                        default=5,
                        type=int,
                        env_var='MAAS_PARALLELISM',
                        help='How many commission or deploy operations to do in '
                        'parallel. NOTE: if you have machine profiles with drive '
                        'exclusions,  parallel deployments are DISABLED as it requires '
                        'interactive responses unless --force is used')
    parser.add_argument('--limit', nargs='+',
                        help='List of entries from the CSV to limit this run to'
                       )
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--list-profiles',
                       action='store_true',
                       help='List Available machine profiles')
    group.add_argument('-S',
                       '--show-profile',
                       help='Show machine profile <>')
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    args = parser.parse_args()
    setup_logger(args)
    print(parser.format_values())
    if args.debug_level != 'NOTSET':
        LOGGER.debug('Debugging enabled')
    if args.internal_config:
        LOGGER.debug('internal_config file set to %s', args.internal_config)
    if args.debug_level:
        LOGGER.debug('debug level set to %s', args.debug_level)
    if args.list_profiles:
        LOGGER.debug('List profiles')
    if args.show_profile:
        LOGGER.debug('Show profile %s', args.show_profile)
    if args.input_csv:
        LOGGER.debug('Input CSV file %s', args.input_csv)
    if args.commission:
        LOGGER.debug('Told to Commission')
    if args.deploy:
        LOGGER.debug('Told to Deploy')
    if args.release:
        LOGGER.debug('Told to Release')
    if args.delete:
        LOGGER.debug('Told to Delete')
    if args.lock:
        LOGGER.debug('Told to Lock')
    if args.unlock:
        LOGGER.debug('Told to Unlock')
    if args.force:
        LOGGER.debug('force is set to true')
    if args.limit:
        LOGGER.debug('Limiting was selected')
    if args.maas_proto:
        LOGGER.debug('MaaS protocol to use %s', args.maas_proto)
    if args.maas_port:
        LOGGER.debug("MaaS port to use %i", args.maas_port)
    if args.maas_server:
        LOGGER.debug("MaaS server to use %s", args.maas_server)
    if args.foreman_server:
        LOGGER.debug("Foreman server to use %s", args.foreman_server)
    if args.foreman_user:
        LOGGER.debug("Foreman user to use %s", args.foreman_user)
    #if args.foreman_pass:
    #    LOGGER.debug("Foreman password to use %s", args.foreman_pass)
    if args.maas_api_key:
        LOGGER.debug("MaaS API key to use %s", args.maas_api_key)
    return args


def maas_authenticate(args: dict) -> object:
    """ Authenticate to maas using passed profile, if nothing passed prompt """
    if args.maas_api_key is None:
        LOGGER.critical("Password auth doesn't work, possible API problem, "
                        "get an api key and use --maas-api-key instead")
        exit(1)
    else:
        url = "%s://%s:%i/MAAS" % (args.maas_proto,
                                   args.maas_server,
                                   args.maas_port)
        client = maas.client.connect(url, apikey=args.maas_api_key)

    if not client:
        LOGGER.critical("Unable to authenticate to MaaS at %s", url)
        exit(1)
    # Get a reference to self.
    myself = client.users.whoami()
    assert myself.is_admin, "%s is not an admin" % myself.username

    # Check for a MAAS server capability.
    version = client.version.get()
    assert "devices-management" in version.capabilities

    LOGGER.info("Authentication to MaaS successfull")
    return client


def colonify_mac_address(mac: str) -> str:
    """ Takes a non-colon delimited mac and returns a colon delimited one """
    mac = re.sub('[.:-]', '', mac).lower()  # remove delimiters and convert to lower case
    mac = ''.join(mac.split())  # remove whitespaces
    assert len(mac) == 12  # length should be now exactly 12 (eg. 00005e005300)
    assert mac.isalnum()  # should only contain letters and numbers
    # convert mac in canonical form (eg. 00:00:5e:00:53:00)
    mac = ":".join(["%s" % (mac[i:i+2]) for i in range(0, 12, 2)])
    return mac


def add_machine(client: object, row: dict, skip_custom_commission: bool = False) -> object:
    """ add and commisssion machines """

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    # Parse out the mac addresses from the encoded field
    mac_addys = []
    bond_macs = row['macs'].split(' ')
    if ';' in row['macs']:
        LOGGER.debug("Using mac addresses linked to bonds")
        LOGGER.debug("Bond_macs is %s", bond_macs)
        for interface in bond_macs:
            LOGGER.debug("Interface %s", interface)
            bmac = interface.split(';')
            LOGGER.debug("Bond name %s, mac: %s", bmac[0], colonify_mac_address(bmac[1]))
            mac_addys.append(bmac[1])
    else:
        for mac in bond_macs:
            mac_addys.append(colonify_mac_address(mac))

    LOGGER.info("Adding new machine %s.%s", row['shortname'], row['domain'])

    nodes = client.nodes.read(hostnames=[row['shortname']])
    if nodes:
        LOGGER.info("%s: Is already known to maas, initiating custom commissioning",
                    row['shortname'])
        for node in nodes:
            machine = node.as_machine()
            custom_commission(machine=machine, skip_custom_commission=skip_custom_commission)
            return machine

    LOGGER.info("%s: Didn't find it by name, trying to add it",
                row['shortname'])
    try:
        machine = client.machines.create(
            architecture="amd64",
            mac_addresses=mac_addys[0],
            power_type=row['power'],
            power_parameters={
                "power_address": row['powerip'],
                "power_user": row['poweruser'],
                "power_pass": row['powerpass'],
                },
            hostname=row['shortname'],
            domain=row['domain'])
    except maas.client.bones.CallError as err:
        if "No rack controllers can acess the BMC" in str(err.content):
            LOGGER.info("%s: Possible IPMI Credentials or firmware issue, aborting",
                        row['shortname'])
            exit(1)
        if "Hostname already exists" in str(err.content):
            LOGGER.info("%s: is already known to maas",
                        row['shortname'])
        if "already in use on" in str(err.content):
            machine_name = str(err.content).partition("already in use on")[2].split()[0].rstrip('.')
            LOGGER.info("%s: Found pre-existing machine %s as %s",
                        row['shortname'],
                        row['shortname'],
                        machine_name)
            nodes = client.nodes.read(hostnames=[machine_name])
            if not nodes:
                LOGGER.error("%s: Unable to find machine %s", row['shortname'], machine_name)
            else:
                for node in nodes:
                    machine = node.as_machine()
                    dom = get_domain_object(client=client, domain=row['domain'])
                    LOGGER.info("%s: Renaming %s to %s.%s",
                                row['shortname'],
                                machine_name,
                                row['shortname'],
                                row['domain'])
                    machine.hostname = row['shortname']
                    machine.domain = dom
                    try:
                        machine.save()
                    except maas.client.bones.CallError as err:
                        LOGGER.warning("%s: machine save error %s",
                           machine.hostname,
                           err.content)
                        return false

                    custom_commission(machine=machine,
                                      skip_custom_commission=skip_custom_commission)
                    return machine
        else:
            LOGGER.error("%s: Error on line %i, trying to add machine %s, error %s",
                         LINE(),
                         row['shortname'],
                         err.content)

    # Possible cases here:
    # 1. Machine was previously on, so when commission was initiated
    #    it needs to power cycle it first
    # 2. Machine was previously off, so when commission is initiated
    #    it powers it on
    LOGGER.info("%s: Make sure machine is on", machine.hostname)
    last_pwr_state = PowerState.UNKNOWN
    while True:
        time.sleep(1)
        try:
            machine.refresh()
        except maas.client.bones.CallError as err:
            LOGGER.warning("%s: machine refresh error %s, continuing",
                           machine.hostname,
                           err.content)
            continue
        try:
            pwr_state = machine.query_power_state()
        except maas.client.bones.CallError as err:
            LOGGER.warning("%s: machine query_power_state error %s, continuing",
                           machine.hostname,
                           err.content)
            continue
        if last_pwr_state == PowerState.ON and pwr_state == PowerState.OFF:
            LOGGER.info("%s: Last state on, currently off")
            last_pwr_state = pwr_state
            continue
        if pwr_state == PowerState.OFF:
            LOGGER.info("%s: Currently off", machine.hostname)
            last_pwr_state = pwr_state
            continue
        elif pwr_state == PowerState.ON and last_pwr_state == PowerState.OFF:
            LOGGER.info("%s: Last state off, Currently on", machine.hostname)
            last_pwr_state = pwr_state
            continue
        elif pwr_state == PowerState.ON and last_pwr_state == PowerState.ON:
            LOGGER.info("%s: is now powered ON", machine.hostname)
            break

    LOGGER.info("%s: Initiating Abort of auto-commmission", machine.hostname)
    while True:
        try:
            machine.refresh()
        except maas.client.bones.CallError as err:
            LOGGER.warning("%s: machine refresh error %s, continuing",
                           machine.hostname,
                           err.content)
            continue
        if machine.status == NodeStatus.COMMISSIONING:
            try:
                machine.abort()
            except maas.client.bones.CallError as err:
                LOGGER.warning("%s: Abort failed (%s)",
                               machine.hostname,
                               err.content)
            time.sleep(3)
            continue
        elif machine.status == NodeStatus.DEFAULT:
            pwr_state = machine.query_power_state()
            if pwr_state == PowerState.OFF:
                LOGGER.info("%s: is now in NEW/OFF state", machine.hostname)
                break
            else:
                continue

    LOGGER.info("%s: Running commission with custom scripts", machine.hostname)
    custom_commission(machine=machine, skip_custom_commission=skip_custom_commission)

    return machine


def get_domain_object(client: object = None, domain: str = None,) -> object:
    """ Get domains list from maas, match str and return object """
    try:
        doms = client.domains.list()
    except maas.client.bones.CallError as err:
        LOGGER.warning("Failed to retrieve domain list, %s",
                       err.content)
    for dom in doms:
        if dom.name == domain:
            return dom
    return None


def custom_commission(machine: object = None, skip_custom_commission: bool = False) -> None:
    """ Initiate custom commissioning """
    while True:
        try:
            machine.refresh()
        except maas.client.bones.CallError as err:
            LOGGER.warning("%s: machine refresh error %s, continuing",
                           machine.hostname,
                           err.content)
            continue
        if machine.status != NodeStatus.COMMISSIONING:
            LOGGER.info("%s: Attempting to start custom commissioning", machine.hostname)
            try:
                if skip_custom_commission:
                    # disabling testing scripts and custom commissioning
                    # sas controller firmware upgrade
                    machine.commission(testing_scripts=[])
                else:
                    machine.commission(commissioning_scripts=["update_firmware"])
            except maas.client.bones.CallError as err:
                #LOGGER.error("Error on line %i, trying to add machine %s, error %s",
                #               LINE(),
                #               row['shortname'],
                #               err.content)
                LOGGER.info("%s: Custom Commission Failed, retrying...", machine.hostname)
        else:
            LOGGER.info("%s: Custom commission initiated successfully", machine.hostname)
            return


def get_list_of_machines_from_maas(client: object, machines: list) -> typing.Tuple[list, list]:
    """ Search for machines and return a list of found and not found """
    found = []
    not_found = machines.copy()
    hostnames = []
    for machine in machines:
        hostnames.append(machine['shortname'])
    nodes = client.nodes.read(hostnames=hostnames)
    for node in nodes:
        for machine in machines:
            if machine['shortname'] == node.hostname:
                machine['system_id'] = node.system_id
                machine['node'] = node
                machine['status'] = node.as_machine().status
                found.append(machine)
                not_found.remove(machine)
    return found, not_found



def get_commissionable_machines(client: object, machines: list) -> list:
    """ Get commissionable machines
    Query maas for known machines
    Figure out which ones are commissionable by their state
    and add them  """
    found, not_found = get_list_of_machines_from_maas(client=client, machines=machines)

    LOGGER.info("Maas knows about %i machines", len(found))
    LOGGER.info("%i machines were't found in maas", len(not_found))

    commissionable_machines = not_found.copy()

    for machine in found:
        if machine['status'] in [
                NodeStatus.NEW,
                NodeStatus.READY,
                NodeStatus.FAILED_COMMISSIONING]:
            LOGGER.info("%s: Is commissionable", machine['shortname'])
            commissionable_machines.append(machine)
        else:
            LOGGER.info("%s: Is NOT commissionable (%s)",
                        machine['shortname'],
                        machine['status'])
    return commissionable_machines


def get_deployable_machines(client: object, machines: list, config: dict) -> list:
    """ Get deployable machines """
    found = []
    hostnames = []
    for machine in machines:
        hostnames.append(machine['shortname'])
    nodes = client.nodes.read(hostnames=hostnames)
    count = 0
    for node in nodes:
        count += 1
        for machine in machines:
            if machine['shortname'] == node.hostname:
                machine['system_id'] = node.system_id
                machine['node'] = node
                machine['status'] = node.as_machine().status
                found.append(machine)

    LOGGER.info("Maas knows about %i machines", count)

    deployable_machines = []

    for machine in found:
        if machine['status'] in [
                NodeStatus.READY]:
            if machine['machine_profile'] not in config['machine_profiles']:
                LOGGER.error("Error on line %i, Machine profile (%s) "
                             "isn't found, skipping host",
                             LINE(),
                             machine['machine_profile'])
            else:
                LOGGER.info("%s: Is deployable", machine['shortname'])
                deployable_machines.append(machine)
        else:
            LOGGER.info("%s: Is NOT deployable (%s)",
                        machine['shortname'],
                        machine['status'])
    return deployable_machines


def delete_machines(client: object, machines_to_delete: list, parallelism: int) -> None:
    """ Delete's machines in maas """
    with ThreadPoolExecutorStackTraced(max_workers=(parallelism)) as executor:
        future_to_machine = {executor.submit(delete_machine,
                                             client,
                                             name['shortname']): \
                                                name for name in machines_to_delete}
        for future in concurrent.futures.as_completed(future_to_machine):
            row = future_to_machine[future]
            try:
                data = future.result()
            except Exception as exc:
                LOGGER.error("%r generated an exception: %s", row, exc)


def delete_machine(client: object, name: str) -> None:
    """ Threaded deleter Delete's machines in maas """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    nodes = client.nodes.read(hostnames=[name])
    if not nodes:
        LOGGER.warning("%s: Is not known to maas", name)
    for node in nodes:
        if node.hostname == name:
            machine = node.as_machine()
            try:
                LOGGER.info("%s: Deleting", machine.hostname)
                machine.delete()
            except maas.client.bones.CallError as err:
                LOGGER.error("Error on line %i, trying to delete machine %s, error %s",
                             LINE(),
                             machine.hostname,
                             err.content)


def unlock_machines(client: object, machines_to_unlock: list, parallelism: int) -> None:
    """ Unlock's machines in maas """
    with ThreadPoolExecutorStackTraced(max_workers=(parallelism)) as executor:
        future_to_machine = {executor.submit(unlock_machine,
                                             client,
                                             name['shortname']): \
                                                 name for name in machines_to_unlock}
        for future in concurrent.futures.as_completed(future_to_machine):
            row = future_to_machine[future]
            try:
                data = future.result()
            except Exception as exc:
                LOGGER.error("%r generated an exception: %s", row, exc)


def unlock_machine(client: object, name: str) -> object:
    """ Threaded unlocker """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    nodes = client.nodes.read(hostnames=[name])
    if not nodes:
        LOGGER.warning("%s: Is not known to maas", name)
    for node in nodes:
        if node.hostname == name:
            machine = node.as_machine()
            if machine.locked:
                try:
                    LOGGER.info("%s: Unlocking", machine.hostname)
                    machine.unlock(
                        comment="Unlocked by Maasterblaster user: " + os.environ["USER"])
                except maas.client.bones.CallError as err:
                    LOGGER.error("Error on line %i, trying to unlock machine %s, error %s",
                                 LINE(),
                                 machine.hostname,
                                 err.content)
            else:
                LOGGER.info("%s: isn't locked", machine.hostname)


def lock_machines(client: object, machines_to_lock: list, parallelism: int) -> None:
    """ lock's machines in maas """
    with ThreadPoolExecutorStackTraced(max_workers=(parallelism)) as executor:
        future_to_machine = {executor.submit(lock_machine,
                                             client,
                                             name['shortname']): name for name in machines_to_lock}
        for future in concurrent.futures.as_completed(future_to_machine):
            row = future_to_machine[future]
            try:
                data = future.result()
            except Exception as exc:
                LOGGER.error("%r generated an exception: %s", row, exc)

def lock_machine(client: object, name: str) -> object:
    """ Threaded locker """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    nodes = client.nodes.read(hostnames=[name])
    if not nodes:
        LOGGER.warning("%s: Is not known to maas", name)
    for node in nodes:
        if node.hostname == name:
            machine = node.as_machine()
            if machine.status != NodeStatus.DEPLOYED:
                LOGGER.warning("%s: Is not deployed, cannot lock", machine.hostname)
            elif not machine.locked:
                try:
                    LOGGER.info("%s: Locking", machine.hostname)
                    machine.lock(
                        comment="Locked by Maasterblaster user: " + os.environ["USER"])
                except maas.client.bones.CallError as err:
                    LOGGER.error("Error on line %i, trying to lock machine %s, error %s",
                                 LINE(),
                                 machine.hostname,
                                 err.content)
            else:
                LOGGER.info("%s: is already locked", machine.hostname)


def release_machines(client: object, args: dict, to_release: list, parallelism: int) -> None:
    """ Release's machines in maas """
    with ThreadPoolExecutorStackTraced(max_workers=(parallelism)) as executor:
        future_to_machine = {executor.submit(release_machine,
                                             client,
                                             args,
                                             name['shortname'],
                                             name['domain']): name for name in to_release}
        for future in concurrent.futures.as_completed(future_to_machine):
            row = future_to_machine[future]
            try:
                data = future.result()
            except Exception as exc:
                LOGGER.error("%r generated an exception: %s", row, exc)


def release_machine(client: object, args: dict, name: str, domain: str) -> None:
    """ Threaded Releaser """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    nodes = client.nodes.read(hostnames=[name])
    if not nodes:
        LOGGER.warning("%s: Is not known to maas", name)
    for node in nodes:
        if node.hostname == name:
            machine = node.as_machine()
#            if machine.status not in [
#                    NodeStatus.DEPLOYED,
#                    NodeStatus.FAILED_DEPLOYMENT,
#                    NodeStatus.ALLOCATED,
#            ]:
#                LOGGER.warning("%s: Is not deployed, cannot release", machine.hostname)
#            elif machine.locked:
            if machine.locked:
                LOGGER.error("%s: is locked, you need to unlock it first", machine.hostname)
            elif not machine.locked:
                try:
                    LOGGER.info("%s: Releasing", machine.hostname)
                    clear_foreman_cert_via_rundeck(args, machine.hostname + "." + domain)
                    clear_salt_key_via_rundeck(args, machine.hostname)
                    machine.release(
                        comment="Released by Maasterblaster user: " + os.environ["USER"])
                except maas.client.bones.CallError as err:
                    LOGGER.error("Error on line %i, trying to release machine %s, error %s",
                                 LINE(),
                                 machine.hostname,
                                 err.content)
            else:
                LOGGER.info("%s: is already released", machine.hostname)


def clear_foreman_cert_via_rundeck(args: dict, fqdn: str) -> None:
    """ Makes curl call to rundeck to clear the puppet cert for ths FQDN """
    LOGGER.info("%s: Attempting curl call to clear puppet cert via rundeck", fqdn)
    url = 'https://' + \
            args.rundeck_server + \
            '/api/32/job/' + \
            args.rundeck_clear_puppet_key_jobid + '/run'
    headers = {'Accept': 'application/json',
               'X-Rundeck-Auth-Token': args.rundeck_api_key,
               'Content-Type': 'application/json'}
    payload = '{"argString":"-FQDN ' + fqdn +'"}'
    # Debug
    #print("URL " + url + '\n')
    #print(headers)
    #print(payload)
    response = requests.post(url, data=payload, headers=headers)
    result = response.json()
    if 'error' in result:
        LOGGER.error("%s: Failure calling rundeck to clear puppet cert: %s", fqdn, result["error"])
    else:
        LOGGER.info("%s: Success triggering puppet cert cleanup", fqdn)




def clear_salt_key_via_rundeck(args: dict, hostname: str) -> None:
    """ Makes curl call to rundeck to clear the salt key for ths FQDN """
    LOGGER.info("%s: Attempting curl call to clear salt key via rundeck", hostname)
    url = 'https://' + \
            args.rundeck_server + \
            '/api/32/job/' + \
            args.rundeck_clear_salt_key_jobid + '/run'
    headers = {'Accept': 'application/json',
               'X-Rundeck-Auth-Token': args.rundeck_api_key,
               'Content-Type': 'application/json'}
    payload = '{"argString":"-ServerName ' + hostname +'"}'
    # Debug
    #print("URL " + url + '\n')
    #print(headers)
    #print(payload)
    response = requests.post(url, data=payload, headers=headers)
    result = response.json()
    if 'error' in result:
        LOGGER.error("%s: Failure calling rundeck to clear salt key: %s", hostname, result["error"])
    else:
        LOGGER.info("%s: Success triggering salt key cleanup", hostname)



def abort_machines(client: object, machines_to_abort: list, parallelism: int) -> None:
    """ Abort's machines in maas """
    with ThreadPoolExecutorStackTraced(max_workers=(parallelism)) as executor:
        future_to_machine = {executor.submit(abort_machine,
                                             client,
                                             name['shortname']): name for name in machines_to_abort}
        for future in concurrent.futures.as_completed(future_to_machine):
            row = future_to_machine[future]
            try:
                data = future.result()
            except Exception as exc:
                LOGGER.error("%r generated an exception: %s", row, exc)


def abort_machine(client: object, name: str) -> None:
    """ Threaded Aborter """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    nodes = client.nodes.read(hostnames=[name])
    if not nodes:
        LOGGER.warning("%s: Is not known to maas", name)
    for node in nodes:
        if node.hostname == name:
            machine = node.as_machine()
            if machine.status  in [
                    NodeStatus.DEPLOYING,
                    NodeStatus.COMMISSIONING,
                    NodeStatus.TESTING,
            ]:
                try:
                    LOGGER.info("%s: Aborting", machine.hostname)
                    machine.abort(
                        comment="Aborted by Maasterblaster user: " + os.environ["USER"])
                except maas.client.bones.CallError as err:
                    LOGGER.error("Error on line %i, trying to abort machine %s, error %s",
                                 LINE(),
                                 machine.hostname,
                                 err.content)
            else:
                LOGGER.warning("%s: Is not deploying, commissioning or testing cannot abort",
                               machine.hostname)



def add_machines(client: object,
                 machines_to_add: list,
                 parallelism: int = 1,
                 skip_custom_commission: bool = False) -> list:
    """ Add new machines to maas which auto-commissions """
    new_machines = []
    add_list = get_commissionable_machines(client=client, machines=machines_to_add)

    if not add_list:
        LOGGER.warning("No machines are in a commissionable state")
        return None
    # Threadpool with async
    LOGGER.info("Commissioning in parallel (%i) threads", parallelism)
    with ThreadPoolExecutorStackTraced(max_workers=parallelism) as executor:
        # Start the add machines...
        future_to_machine = {executor.submit(add_machine,
                                             client,
                                             row,
                                             skip_custom_commission): row for row in add_list}
        for future in concurrent.futures.as_completed(future_to_machine):
            row = future_to_machine[future]
            try:
                data = future.result()
            except Exception as exc:
                LOGGER.error("%r generated an exception: %s", row, exc)
            else:
                new_machines.append(data)

    return new_machines


@asynchronous
async def monitor_deployment(client: object, machines: list) -> None:
    """ Monitors the deployment status of machines until they complete """
    LOGGER.info("monitor_deployment...")

    failed_machines = []
    completed_machines = []
    hostnames = []
    if not machines:
        LOGGER.warning("No machines to deploy")
        return
    start = calendar.timegm(time.gmtime())
    while machines:
        time.sleep(30)
        now = calendar.timegm(time.gmtime())
        LOGGER.info("Elapsed time: %s", time.strftime("%-H:%M:%S", time.gmtime(now-start)))
        for machine in machines:
            hostnames.append(machine.hostname)
        nodes = await client.nodes.read(hostnames=hostnames)
        for node in nodes:
            for machine in machines:
                if machine.hostname == node.hostname:
                    status = node.as_machine().status
                    if status == NodeStatus.DEPLOYING:
                        LOGGER.info("%s: (%s) is deploying, %s",
                                    node.hostname,
                                    node.system_id,
                                    node.as_machine().status_message)
                    elif status == NodeStatus.DEPLOYED:
                        LOGGER.info("%s: (%s) has finished deploying",
                                    node.hostname,
                                    node.system_id)
                        completed_machines.append(machine)
                        machines.remove(machine)
                    else:  # Failure
                        LOGGER.info("%s: (%s) has FAILED deployment",
                                    node.hostname,
                                    node.system_id)
                        failed_machines.append(machine)
                        machines.remove(machine)
    if failed_machines:
        for machine in failed_machines:
            LOGGER.critical("%s: transitioned to unexpected status - %s",
                            machine.hostname, machine.status_name)
    else:
        LOGGER.info("Successfully deployed %d machines.",
                    len(completed_machines))
    return


def power_off_machines(machines: list) -> None:
    """ Poweroff machines after commissioning to free up IP's """
    for machine in machines:
        LOGGER.info("%s: Powering off",
                    machine.hostname)
        machine.power_off()


@asynchronous
async def commission_machines(client: object,
                              new_machines: list = None,
                              skip_custom_commission: bool = False) -> list:
    """ Commission the machines, this should be fast, but isn't really"""
    LOGGER.info("commission_machines...")

    if not new_machines:
        LOGGER.warning("No machines to commission")
        return
    for machine in new_machines:
        LOGGER.info("%s: Attempting to commission (%s)",
                    machine.hostname,
                    machine.system_id)
        if machine.status in [NodeStatus.NEW, NodeStatus.READY]:
            try:
                # disablind testing scripts and custom commissioning sas controller firmware upgrade
                if skip_custom_commission:
                    await machine.commission(testing_scripts=[])
                else:
                    await machine.commission(commissioning_scripts=["update_firmware"])
            except maas.client.bones.CallError as err:
                LOGGER.warning("Error on line %i, trying to commission "
                               "machine %s, error %s, trying again in 5 sec",
                               LINE(),
                               machine.hostname,
                               err.content)
                await asyncio.sleep(15)
                LOGGER.info("%s: Attempt retry of custom commissioning",
                            machine.hostname)
                try:
                    # disabling testing scripts and custom commissioning
                    # sas controller firmware upgrade
                    if skip_custom_commission:
                        await machine.commission(testing_scripts=[])
                    else:
                        await machine.commission(commissioning_scripts=["update_firmware"])
                except maas.client.bones.CallError as err:
                    LOGGER.critical("Error on line %i, trying to commission "
                                    "machine %s, error %s, 2nd failure, "
                                    "not trying again",
                                    LINE(),
                                    machine.hostname,
                                    err.content)
                LOGGER.info("%s: Success!", machine.hostname)


    # Wait until all machines are ready
    failed_machines = []
    completed_machines = []
    hostnames = []
    start = calendar.timegm(time.gmtime())
    #while len(new_machines) > 0:
    while new_machines:
        time.sleep(30)
        now = calendar.timegm(time.gmtime())
        LOGGER.info("Elapsed time: %s", time.strftime("%-H:%M:%S", time.gmtime(now-start)))
        for machine in new_machines:
            hostnames.append(machine.hostname)
        nodes = await client.nodes.read(hostnames=hostnames)
        for node in nodes:
            for machine in new_machines:
                if machine.hostname == node.hostname:
                    status = node.as_machine().status
                    if status in [
                            NodeStatus.COMMISSIONING,
                            NodeStatus.TESTING
                        ]:
                        # Machine is still commissioning or testing
                        if status == NodeStatus.COMMISSIONING:
                            _status = "Commissioning"
                        else:
                            _status = "Testing"
                        LOGGER.info("%s: (%s) is in state %s, %s",
                                    node.hostname,
                                    node.system_id,
                                    _status,
                                    node.as_machine().status_message)
                    elif status == NodeStatus.READY:
                        # Machine is complete
                        LOGGER.info("%s: (%s) has finished commissioning",
                                    node.hostname, node.system_id)
                        completed_machines.append(machine)
                        new_machines.remove(machine)
                    else:
                        # Machine has failed
                        LOGGER.error("%s: (%s) has FAILED commissioning",
                                     node.hostname, node.system_id)
                        failed_machines.append(machine)
                        new_machines.remove(machine)

    # Print message if any machines failed to commission.
    #if len(failed_machines) > 0:
    if failed_machines:
        for machine in failed_machines:
            LOGGER.critical("%s: transitioned to unexpected status - %s",
                            machine.hostname, machine.status_name)
    else:
        LOGGER.info("Successfully commissioned %d machines.",
                    len(completed_machines))

    return completed_machines

def cleanup_machine(machine: object) -> None:
    """ Cleans up customizations of machine to defaualts """
    LOGGER.info("%s: cleaning up machine", machine.hostname)
    machine.restore_default_configuration()
#    machine.restore_networking_configuration()
    for interface in machine.interfaces:
        if 'allocated' in interface.tags:
            LOGGER.info("%s: Found \"allocated\" tag on interface %s, removing it",
                        machine.hostname,
                        interface.name)
            interface.tags.remove('allocated')
            interface.save()
    try:
        machine.restore_storage_configuration()
    except maas.client.bones.CallError as err:
        LOGGER.warning("%s: Error on line %i, trying to restore storage " \
                       "configuration, error %s",
                       machine.hostname,
                       LINE(),
                       err.content)
        LOGGER.warning("%s: Doing manual cleanup of storage on device",
                       machine.hostname)
    # Logical volumes first
    for disk in machine.block_devices:
        if disk.type == maas.client.enum.BlockDeviceType.VIRTUAL and \
        not re.search("md", disk.name):
            LOGGER.info("%s: deleting virtual block device %s",
                        machine.hostname,
                        disk.name)
            disk.delete()

    # Volume Groups
    for volume_group in machine.volume_groups:
        LOGGER.info("%s: deleting Volume Group",
                    machine.hostname)
        volume_group.delete()

    # MD arrays
    for disk in machine.block_devices:
        if disk.type == maas.client.enum.BlockDeviceType.VIRTUAL and re.search("md", disk.name):
            LOGGER.info("%s: deleting virtual block device %s",
                        machine.hostname,
                        disk.name)
            disk.delete()

    # Physical Disks
    for disk in machine.block_devices:
        #LOGGER.info("%s: deleting partitions from block device %s",
        #            machine.hostname,
        #            disk.name)
        if disk.type == maas.client.enum.BlockDeviceType.PHYSICAL:
            if 'allocated' in disk.tags:
                LOGGER.info("%s: Found \"allocated\" tag on disk, removing it",
                            machine.hostname)
                disk.tags.remove('allocated')
                disk.save()
            count = 1
            for partition in disk.partitions:
                LOGGER.info("%s: deleting partition %i from block device %s",
                            machine.hostname,
                            count,
                            disk.name)
                partition.delete()
                count = count + 1

    for disk in machine.block_devices:
        if disk.type == maas.client.enum.BlockDeviceType.PHYSICAL:
            if 'allocated' in disk.tags:
                LOGGER.info("%s: Found \"allocated\" tag on disk %s, removing it",
                            machine.hostname,
                            disk.name)
                disk.tags.remove('allocated')
                disk.save()
    LOGGER.info("%s: Refreshing machine", machine.hostname)
    machine.refresh()
    LOGGER.info("%s: Refresh complete", machine.hostname)
    LOGGER.info("%s: Cleanup complete", machine.hostname)


def exclude_disks_by_criteria(machine: object, config: dict) -> int:
    """ Deletes disks from maas view based on criteria

    This uses find_disks_by_criteria() to get a list of
    all disks matching the criteria then removes them from maas's
    view with disk.delete, so that maas don't touch, erase or
    reformat these devices on deployment

    :param machine: Machine object
    :param config: Config dictionary for this disk set
    :type machine: maas.client.machine object
    :type config: Dictionary for this disk set

    If criteria matches, remove this drive from the config so
    it is not touched, erased or otherwise molested
    """

    count = 0
    disks = find_disks_by_criteria(machine=machine, config=config, raids=None)
    for disk in disks:
        count += 1
        disk.delete()
    return count


def find_disk_by_name(config: dict, disk: object, machine: object) -> bool:
    """ Find disks mactching name in config """
    namematch = True
    if 'disks' in config.keys():
        if disk.name in config['disks']:
            LOGGER.info("%s: Disk %s matched on disk match_on criteria",
                        machine.hostname,
                        disk.name)
        else:
            LOGGER.info("%s: Disk %s DID NOT match on disk match_on criteria",
                        machine.hostname,
                        disk.name)
            namematch = False
    return namematch


def find_disk_greaterthan(config: dict, disk: object, machine: object) -> bool:
    """ Find disks larger than config specified size """
    greaterthan = True

    if 'size_greaterthan' in config.keys():
        try:
            match_size = get_size_in_bytes( \
                config['size_greaterthan'], \
                disk.available_size)
        except AttributeError:
            match_size = get_size_in_bytes( \
                config['size_greaterthan'], \
                disk.size)

        if disk.size > match_size:
            LOGGER.info("%s: Disk %s passes on match_on criteria "
                        "for size_greaterthan (%i > %i)",
                        machine.hostname,
                        disk.name,
                        disk.size,
                        match_size)
            greaterthan = True
        else:
            LOGGER.info("%s: Disk %s FAILS on match_on criteria "
                        "for size_greaterthan (%i <= %i)",
                        machine.hostname,
                        disk.name,
                        disk.size,
                        match_size)
            greaterthan = False

    return greaterthan

def find_disk_lessthan(config: dict, disk: object, machine: object) -> bool:
    """ Find disks smaller than config specified size """
    lessthan = True
    if 'size_lessthan' in config.keys():
        try:
            match_size = get_size_in_bytes( \
                config['size_lessthan'], \
                disk.available_size)
        except:
            match_size = get_size_in_bytes( \
                config['size_lessthan'], \
                disk.size)
        if disk.size < match_size:
            LOGGER.info("%s: Disk %s passes on match_on criteria for "
                        "size_lessthan (%i < %i)",
                        machine.hostname,
                        disk.name,
                        disk.size,
                        match_size)
            lessthan = True
        else:
            LOGGER.info("%s: Disk %s FAILS on match_on criteria for "
                        "size_lessthan (%i <= %i)",
                        machine.hostname,
                        disk.name,
                        disk.size,
                        match_size)
            lessthan = False
    return lessthan


def find_disk_by_tags(config: dict, disk: object, machine: object) -> bool:
    """ Find disks by tags from config """
    tagsmatch = True
    if 'tags' in config.keys():
        for tag in config['tags']:
            if tag in disk.tags:
                LOGGER.info("%s: Disk %s passes on match_on criteria for "
                            "tags (%s found)",
                            machine.hostname,
                            disk.name,
                            tag)
                tagsmatch = True
            else:
                LOGGER.info("%s: Disk %s fails on match_on criteria for "
                            "tags (%s NOT found)",
                            machine.hostname,
                            disk.name,
                            tag)
                tagsmatch = False
    return tagsmatch


def find_disk_by_model(config: dict, disk: object, machine: object) -> bool:
    """ Find disks by model from config """
    modelmatch = True
    if 'model' in config.keys():
        if re.search(config['model'], disk.model):
            LOGGER.info("%s: Disk %s passes on match_on criteria for "
                        "model (%s found)",
                        machine.hostname,
                        disk.model,
                        config['model'])
            modelmatch = True
        else:
            LOGGER.info("%s: Disk %s fails on match_on criteria for "
                        "model (%s NOT found)",
                        machine.hostname,
                        disk.model,
                        config['model'])
            modelmatch = False
    return modelmatch


def find_disk_by_type(config: dict, disk: object, machine: object) -> bool:
    """ Find disk by type from config """
    typematch = True
    if 'type' in config.keys():
        if re.search(config['type'], disk.type):
            LOGGER.info("%s: Disk %s passes on match_on criteria for "
                        "model (%s found)",
                        machine.hostname,
                        disk.type,
                        config['type'])
            typematch = True
        else:
            LOGGER.info("%s: Disk %s fails on match_on criteria for "
                        "model (%s NOT found)",
                        machine.hostname,
                        disk.type,
                        config['type'])
            typematch = False
    return typematch



def get_physical_disks(machine: object, config: dict, max_devices: int) -> list:
    """ Returns array of physical disks matching criteria """
    count = 0
    disks = []
    for disk in machine.block_devices:
        if 'allocated' in disk.tags:
            LOGGER.info("%s: Disk %s is already allocated skipping it",
                        machine.hostname,
                        disk.name)
            continue

        namematch = find_disk_by_name(config, disk, machine)
        greaterthan = find_disk_greaterthan(config, disk, machine)
        lessthan = find_disk_lessthan(config, disk, machine)
        tagsmatch = find_disk_by_tags(config, disk, machine)
        modelmatch = find_disk_by_model(config, disk, machine)
        typematch = find_disk_by_type(config, disk, machine)

        if namematch and modelmatch and typematch and tagsmatch and lessthan and greaterthan:
            LOGGER.info("%s: We matched on all criteria for %s, adding disk",
                        machine.hostname,
                        disk.name)
            disk.tags.append('allocated')
            disk.save()
            disks.append(disk)
            count = count + 1
        else:
            LOGGER.warning("%s: Didn't match on criteria for %s",
                           machine.hostname,
                           disk.name)
        if count >= max_devices:
            LOGGER.info("%s: We met the max_devices count, breaking out",
                        machine.hostname)
            break
    return disks


def find_disks_by_criteria(machine: object, config: dict, raids: dict) -> list:
    """ Returns array of disks matching criteria

    :param machine: Machine object
    :param config: Config dictionary for this disk set
    :type machine: maas.client.machine object
    :type config: Dictionary for this disk set
    :rtype: Array for disk objects
    """

    # Handle match criteria, all must be true to be added
    if 'match_on' in config.keys():
        if 'max_devices' in config['match_on'].keys():
            max_devices = config['match_on']['max_devices']
        else:
            max_devices = 99999
        count = 0
        if 'children' in config['match_on'].keys():
            LOGGER.info("Trying to get raid sets")
            disks = raids[config['match_on']['children']]
            LOGGER.info("Got them ")
        else:
            disks = get_physical_disks(machine, config['match_on'], max_devices)

    if 'raidlevel' in config.keys():
        if config['raidlevel'] == 1 or config['raidlevel'] == 0:
            if len(disks) < 2:
                LOGGER.error("%s: Disks not properly filtered for RAID0 "
                             "or RAID1 config, only found %i",
                             machine.hostname,
                             len(disks))
                traceback.print_stack(file=sys.stdout)
                exit(1)
        if config['raidlevel'] == 5:
            if len(disks) < 3:
                LOGGER.error("%s: Disks not properly filtered for RAID5 "
                             "config, only found %i",
                             machine.hostname,
                             len(disks))
                traceback.print_stack(file=sys.stdout)
                exit(1)
        if config['raidlevel'] == 6 or config['raidlevel'] == 10:
            if len(disks) < 4:
                LOGGER.error("%s: Disks not properly filtered for RAID5 config, only found %i",
                             machine.hostname,
                             len(disks))
                traceback.print_stack(file=sys.stdout)
                exit(1)

    return disks


def get_size_in_bytes(value, disk_total_size: int, fudge: bool = True) -> int:
    """ Checks input, if its pure numeric, it returns if, if it
    has a suffix like G, M or T, scale it appropriately,
    if it ends with % calculate the % of disk_total_size with a floor divide"""
    if isinstance(value, int):
        return value
    try:
        num_in_bytes = 0
        input_number = int("".join([s for s in value if s in string.digits]))
        postfix = "".join([s for s in value if s in string.ascii_letters+'%']).upper()

        if postfix == "B":
            num_in_bytes = input_number
        if postfix == "KB" or postfix == "K":
            num_in_bytes = input_number * 1000
        if postfix == "MB" or postfix == "M":
            num_in_bytes = input_number * 1000 * 1000
        if postfix == "GB" or postfix == "G":
            num_in_bytes = input_number * 1000 * 1000 * 1000
        if postfix == "TB" or postfix == "T":
            num_in_bytes = input_number * 1000 * 1000 * 1000 * 1000
        if postfix == "%":
            num_in_bytes = (disk_total_size * input_number) // 100
    except ValueError:
        num_in_bytes = 0
    if fudge:
        # fudge factor to work around a bug in maas with how it seems to calculate free space
        return num_in_bytes - int(num_in_bytes * DISK_FUDGE)
    else:
        return num_in_bytes


def get_vlan_config(parent_name: str,
                    machine: object,
                    csv_netcfg: dict,
                    subnets: list,
                    vlan_name: str) -> Tuple[object, str, str]:
    """ Compares the vlan passed with the netcfg to get the details """
    subnet = None
    vlan_iface_name = None
    ip_addr = None

    for user_netcfg in csv_netcfg:
        netcfg = csv_netcfg[user_netcfg]
        LOGGER.info("%s: Checking interface %s",
                    machine.hostname,
                    netcfg['name'])
        LOGGER.info("%s: Netcfg: %s",
                    machine.hostname,
                    repr(netcfg))
        LOGGER.info("%s: Parent is %s",
                    machine.hostname,
                    parent_name)
        LOGGER.info("%s: VLAN is %s",
                    machine.hostname,
                    vlan_name)
        if 'parent' in netcfg.keys() and \
                       netcfg['parent'] == parent_name and \
                       netcfg['type'] == "vlan" and \
                       'vlan' in netcfg.keys() and \
                       netcfg['vlan'] == str(vlan_name): # We found it
            subnet = get_maas_subnet(subnets=subnets,
                                     machine=machine,
                                     ip_addr=netcfg['ip'])
            vlan_iface_name = netcfg['name']
            ip_addr = netcfg['ip']
            LOGGER.info("%s: Strict Match Found the vlan interface %s in the csv",
                        machine.hostname,
                        vlan_iface_name)
            break
    # Weaker Test handles only a single vlan
    if subnet is None and vlan_iface_name is None and ip_addr is None:
        for user_netcfg in csv_netcfg:
            netcfg = csv_netcfg[user_netcfg]
            # Weaker test, only works when there is a MAXIMUM of 1 vlan subinterface
            if 'parent' in netcfg.keys() and \
                           netcfg['parent'] == parent_name and \
                           netcfg['type'] == "vlan": # We found it
                subnet = get_maas_subnet(subnets=subnets,
                                         machine=machine,
                                         ip_addr=netcfg['ip'])
                vlan_iface_name = netcfg['name']
                ip_addr = netcfg['ip']
                LOGGER.info("%s: Weak Match Found the vlan interface %s in the csv",
                            machine.hostname,
                            vlan_iface_name)
                break
    return  subnet, vlan_iface_name, ip_addr


def configure_address_on_interface(client: object,
                                   machine: object,
                                   iface_object: object,
                                   iface_name: str,
                                   iface_cfg: dict,
                                   csv_netcfg: dict,
                                   maas_subnets: list,
                                   fabric: str) -> object:
    """ Configures the address on the interface if defined
    :param client: Maas Client object
    :param iface_object: MAAS Interface object we are configuring
    :param iface_name: Interface name, bond0, eth0, br0, etc
    :param iface_cfg: Subset of config.yml for this interface
    :param csv_netcfg: The netcfg csg for this machine from the user
    """
    # Get Subnets from MAAS
    subnet = get_subnet(client=client,
                        machine=machine,
                        iface_name=iface_name,
                        iface_cfg=iface_cfg,
                        csv_netcfg=csv_netcfg,
                        maas_subnets=maas_subnets,
                        fabric=fabric)
    LOGGER.info("%s: Creating the link for the %s interface",
                machine.hostname,
                iface_name)
    if iface_name in csv_netcfg.keys():
        if 'ip' in csv_netcfg[iface_name].keys():
            try:
                iface_object.links.create(mode=maas.client.enum.LinkMode.STATIC,
                                          force=True,
                                          subnet=subnet,
                                          ip_address=csv_netcfg[iface_name]['ip'])
            except maas.client.bones.CallError as err:
                LOGGER.warning("%s: Error on line %i, trying to set "
                               "static IP (%s) on interface %s error(%s):",
                               machine.hostname,
                               LINE(),
                               csv_netcfg[iface_name]['ip'],
                               iface_name,
                               err.content)
                exit(1)
        else:
            LOGGER.info("%s: No IP on %s interface",
                        machine.hostname,
                        iface_name)
            try:
                iface_object.links.create(mode=maas.client.enum.LinkMode.LINK_UP,
                                          force=True,
                                          subnet=subnet)
            except maas.client.bones.CallError as err:
                LOGGER.warning("%s: Error on line %i, trying to set NO IP"
                               "on interface %s error(%s):",
                               machine.hostname,
                               LINE(),
                               iface_name,
                               err.content)
                exit(1)
        if 'default_gateway' in iface_cfg:
            LOGGER.info("%s: Configuring default gateway on interface %s",
                        machine.hostname,
                        iface_name)
            try:
                iface_object.links.create(maas.client.enum.LinkMode.STATIC,
                                          force=True,
                                          subnet=subnet,
                                          ip_address=csv_netcfg[iface_name]['ip'],
                                          default_gateway=iface_cfg['default_gateway'])
            except maas.client.bones.CallError as err:
                LOGGER.critical("%s: Unable to set default gateway to %s "
                                "on interface %s, error(%s)",
                                machine.hostname,
                                iface_cfg['default_gateway'],
                                iface_name,
                                err.content)
                exit(1)
    return subnet


def configure_bridge(client: object,
                     machine: object,
                     iface_name: str,
                     iface_cfg: dict,
                     parent_object: object,
                     csv_netcfg: dict,
                     maas_subnets: list,
                     fabric: str) -> None:
    """ Configures bridge interfaces with the parent of iface_name
    :param client: The maas client object
    :param machine: The maas machine object
    :param iface_name: The interface name,  i.e. bond0, eth0, etc
    :param iface_cfg: The subset of config.yml for this particular interface
    :param iface_object: The interface object we are configuring
    :param csv_netcfg: the parsed Netcfg data fromthe user CSV for this machine
    """
    subnet = get_subnet(client=client,
                        machine=machine,
                        iface_name=iface_name,
                        iface_cfg=iface_cfg,
                        csv_netcfg=csv_netcfg,
                        maas_subnets=maas_subnets,
                        fabric=fabric)
    bridge = iface_cfg
    if 'bridge_stp' in bridge.keys():
        bridge_stp = bridge['bridge_stp']
    else:
        bridge_stp = False
    if 'bridge_forward_delay' in bridge.keys():
        bridge_fd = bridge['bridge_forward_delay']
    else:
        bridge_fd = 0
    try:
        br_vif = machine.interfaces.create(
            name=iface_name,
            interface_type=maas.client.enum.InterfaceType.BRIDGE,
            parent=parent_object,
            bridge_stp=bridge_stp,
            bridge_fd=bridge_fd,
            tags=["allocated"])
        LOGGER.info("%s: Attempting to bring up unbound bridge interface %s",
                    machine.hostname,
                    iface_name)
        br_vif.links.create(maas.client.enum.LinkMode.LINK_UP,
                            force=True,
                            subnet=subnet)

    except maas.client.bones.CallError as err:
        LOGGER.warning("%s: Error on line %i, trying to create bridge interface %s error(%s):",
                       machine.hostname,
                       LINE(),
                       iface_name,
                       err.content)
    configure_address_on_interface(client=client,
                                   machine=machine,
                                   iface_object=br_vif,
                                   iface_name=iface_name,
                                   iface_cfg=iface_cfg,
                                   csv_netcfg=csv_netcfg,
                                   maas_subnets=maas_subnets,
                                   fabric=fabric)


def configure_interface(client: object,
                        machine: object,
                        iface_name: str,
                        iface_cfg: dict,
                        iface_object: object,
                        csv_netcfg: dict,
                        maas_subnets: list,
                        fabric: str) -> None:
    """ Configures a network interface
    :param client: The maas client object
    :param machine: The maas machine object
    :param iface_name: The interface name,  i.e. bond0, eth0, etc
    :param iface_cfg: The subset of config.yml for this particular interface
    :param iface_object: The interface object we are configuring
    :param csv_netcfg: the parsed Netcfg data fromthe user CSV for this machine

        - does it have an IP?
            - What subnet is it on (determine via in_csv param)
            - Does it hold the default gateway?
        - Does it have a bridge associated to it?
            - Does the bridge have an IP
            - Does it hold the default gateway?
        - Does it have any IP aliases?
            - What subnet is it on (determine via in_csv param)
            - Does it hold the default gateway?
        - Does it have any VLAN's?
            - does the VLAN have an IP?
                - Does the bridge have an IP
                - Does it hold the default gateway?
            - Does the VLAN have any bridges?
                - does the bridge have an IP?
                    - Does it hold the default gateway?
            - Does the VLAN have any IP aliases?
                - does the ip_alias have an IP (yes)?
                    - Does it hold the default gateway?
    """


    iface_object.tags = ["allocated"]
    iface_object.save()

    configure_address_on_interface(client=client,
                                   machine=machine,
                                   iface_object=iface_object,
                                   iface_name=iface_name,
                                   iface_cfg=iface_cfg,
                                   csv_netcfg=csv_netcfg,
                                   maas_subnets=maas_subnets,
                                   fabric=fabric)

    if 'bridges' in iface_cfg:
        LOGGER.info("%s: %s has Bridge subinterfaces",
                    machine.hostname,
                    iface_name)
        bridges = iface_cfg['bridges']
        LOGGER.info("%s: Walking bridges for interface %s",
                    machine.hostname,
                    iface_name)
        for bridge in bridges:
            br_iface = bridges[bridge]
            LOGGER.info("%s: Bridge %s parent interface %s",
                        machine.hostname,
                        bridge,
                        iface_name)
            configure_bridge(client=client,
                             machine=machine,
                             iface_name=bridge,
                             iface_cfg=br_iface,
                             parent_object=iface_object,
                             csv_netcfg=csv_netcfg,
                             maas_subnets=maas_subnets,
                             fabric=fabric)
    if 'vlans' in iface_cfg:
        LOGGER.info("%s: %s has VLAN subinterfaces",
                    machine.hostname,
                    iface_name)
        vlans = iface_cfg['vlans']
        LOGGER.info("%s: Walking vlan's for interface %s",
                    machine.hostname,
                    iface_name)
        for vlan in vlans:
            vlan_iface = vlans[vlan]
            LOGGER.info("%s: VLAN %s parent interface %s",
                        machine.hostname,
                        vlan,
                        iface_name)
            configure_vlan(machine=machine,
                           client=client,
                           iface_name=vlan,
                           iface_cfg=vlan_iface,
                           parent_object=iface_object,
                           csv_netcfg=csv_netcfg,
                           maas_subnets=maas_subnets,
                           fabric=fabric)


def configure_vlan(machine: dict,
                   client: object,
                   iface_name: str,
                   iface_cfg: dict,
                   parent_object: object,
                   csv_netcfg: dict,
                   maas_subnets: list,
                   fabric: str):
    """ Configures a vlan network subinterface
    :param client: The maas client object
    :param machine: The maas machine object
    :param iface_name: The interface name,  i.e. bond0, eth0, etc
    :param iface_cfg: The subset of config.yml for this particular interface
    :param parent_object: The parent interface for this vlan subinterface
    :param csv_netcfg: the parsed Netcfg data fromthe user CSV for this machine
    """

    subnet = None
    vlan_iface_name = None

    if 'vlan' in iface_cfg.keys() and 'in_csv' not in iface_cfg.keys(): # Using a defined subnet
        LOGGER.info("%s: Using a defined subnet for a vlan subint, NOT from the csv",
                    machine.hostname)
        LOGGER.info("%s: Fabric for this interface is %s",
                    machine.hostname,
                    fabric)
        fabric_obj = get_fabric(client, fabric)
        vlan = get_vlan_from_vlan_id_and_fabric(fabric=fabric_obj, vid=iface_cfg['vlan'])
        vlan_iface_name = parent_object.name + "." + str(iface_name)
#    if 'subnet' in iface_cfg.keys() and 'in_csv' not in iface_cfg.keys(): #using a defined subnet
#        LOGGER.info("%s: Using a defined subnet for a vlan subint, NOT from the csv",
#                    machine.hostname)
#        subnet = get_maas_subnet(subnets=maas_subnets,
#                                 machine=machine,
#                                 subnet_name=iface_cfg['subnet'])
#        vlan_iface_name = parent_object.name + "." + str(iface_name)
    elif 'in_csv' in iface_cfg.keys():
        LOGGER.info("%s: Using a lookup from the user CSV",
                    machine.hostname)
        subnet, vlan_iface_name, ip_addr = \
                get_vlan_config(parent_name=parent_object.name,
                                machine=machine,
                                csv_netcfg=csv_netcfg,
                                subnets=maas_subnets,
                                vlan_name=iface_name)
        vlan = subnet.vlan
    else:
        LOGGER.critical("%s: Error on line %i, Unable to determine subnet for vlan subinterface %s",
                        machine.hostname,
                        LINE(),
                        iface_name)
        traceback.print_stack(file=sys.stdout)
        exit(1)
    if vlan_iface_name != None:
        LOGGER.info("%s: vlan interface name should be %s",
                    machine.hostname,
                    vlan_iface_name)
        try:
            LOGGER.info("%s: Attempting to add interface %s on %s",
                        machine.hostname,
                        parent_object.name,
                        vlan.name)
            parent_object.vlan = vlan #fabric.vlans.get_default()
            vif = machine.interfaces.create(interface_type=maas.client.enum.InterfaceType.VLAN,
                                            name=vlan_iface_name,
                                            #vlan=subnet.vlan,
                                            vlan=vlan,
                                            parent=parent_object,
                                            tags=["allocated"])
        except maas.client.bones.CallError as err:
            LOGGER.warning("%s: Error on line %i, trying to create interface %s error(%s):",
                           machine.hostname,
                           LINE(),
                           iface_name,
                           err.content)
            traceback.print_stack(file=sys.stdout)
            exit(1)
        # Don't think this is necessary....   vif.vlan = subnet.vlan
        configure_address_on_interface(client=client,
                                       machine=machine,
                                       iface_object=vif,
                                       iface_name=vlan_iface_name,
                                       iface_cfg=iface_cfg,
                                       csv_netcfg=csv_netcfg,
                                       maas_subnets=maas_subnets,
                                       fabric=fabric)
        if 'bridges' in iface_cfg:
            LOGGER.info("%s: %s has Bridge subinterfaces",
                        machine.hostname,
                        vlan_iface_name)
            bridges = iface_cfg['bridges']
            LOGGER.info("%s: Walking bridges for interface %s",
                        machine.hostname,
                        vlan_iface_name)
            for bridge in bridges:
                br_iface = bridges[bridge]
                LOGGER.info("%s: Bridge %s parent interface %s",
                            machine.hostname,
                            bridge,
                            iface_name)
                configure_bridge(client=client,
                                 machine=machine,
                                 iface_name=bridge,
                                 iface_cfg=br_iface,
                                 parent_object=vif,
                                 csv_netcfg=csv_netcfg,
                                 maas_subnets=maas_subnets,
                                 fabric=fabric)


def configure_bonded_interface(machine: dict,
                               client: dict,
                               iface_cfg: dict,
                               iface_name: str,
                               csv_netcfg: dict,
                               csv_macs: dict,
                               maas_subnets: list,
                               fabric: str) -> object:
    """ Configures a bonded interface based on a parameters within the niterface dictionary
    :param machine: The Maas Machine Structure
    :param client: the maas client Structure
    :param iface_cfg: The excerpt froom config.yml for this particular interface
    :param iface_name: The interface name from the config.yml
    :param csv_netcfg: The parsed netcfg from the user CSV for this host
    :param csv_macs: The mac addresses passed from the user in the CSV

    Attempts to get the subnet for this interface's primary network, This can come from a VLAN
    yaml alias like *use1_vlan403, or it cna come from the CSV via an in_csv: tag, This requires
    the netcfg to have a bondX:<some_ip> that we can determine the subnet from, lack of either
    will result in an un-ip'd interface
    """
    slaves = []
    subnet = get_subnet(client=client,
                        machine=machine,
                        iface_name=iface_name,
                        iface_cfg=iface_cfg['networks']['primary'],
                        csv_netcfg=csv_netcfg,
                        maas_subnets=maas_subnets,
                        fabric=fabric)
    if 'by_name' in iface_cfg['slaves']:
        LOGGER.warning("%s: Configuring bond by interface names, "
                       "this is UNRELIABLE use by_mac instead",
                       machine.hostname)
        for slave in iface_cfg['slaves']['by_name']:
            for machine_iface in machine.interfaces:
                if slave == machine_iface.name:
                    LOGGER.info("%s: by_name matched on interface named %s",
                                machine.hostname,
                                slave)
                    slaves.append(machine_iface)
        if len(slaves) != len(iface_cfg['slaves']['by_name']):
            LOGGER.critical("%s: Error on line %i, Unable to find all slave interfaces!",
                            machine.hostname,
                            LINE())
            LOGGER.critical("%s: Only found %i",
                            machine.hostname,
                            len(slaves))
            for slave in slaves:
                LOGGER.critical("%s: Found %s",
                                machine.hostname,
                                slave.name)
            traceback.print_stack(file=sys.stdout)
            exit(1)
    elif 'by_mac' in iface_cfg['slaves']:
        LOGGER.info("%s: Configuring bond by interface mac_addresses",
                    machine.hostname)
        if 'in_csv' in iface_cfg['slaves']['by_mac']:
            for mac in csv_macs.split(' '):
                LOGGER.info("%s: Checking if %s matches",
                            machine.hostname, colonify_mac_address(mac.split(';')[1]))
                for machine_iface in machine.interfaces:
                    LOGGER.info("%s: - %s",
                                machine.hostname,
                                machine_iface.mac_address)
                    if ';' in mac: # Tagged mac addresses for bonds
                        bond_mac = mac.split(';')
                        if bond_mac[0] == iface_name:
                            clean_mac = colonify_mac_address(bond_mac[1])
                            if clean_mac == machine_iface.mac_address:
                                LOGGER.info("%s: FOUND IT (%s from %s)",
                                            machine.hostname,
                                            clean_mac,
                                            machine_iface.name)
                                slaves.append(machine_iface)
                    else:
                        clean_mac = colonify_mac_address(mac)
                        if clean_mac == machine_iface.mac_address:
                            LOGGER.info("%s: FOUND IT (%s from %s)",
                                        machine.hostname,
                                        clean_mac,
                                        machine_iface.name)
                            slaves.append(machine_iface)
    else:
        LOGGER.critical("%s: Error on line %i, Unable to determine slaves, check configs!",
                        machine.hostname,
                        LINE())
        traceback.print_stack(file=sys.stdout)
        exit(1)
    LOGGER.info("%s: Setting slave links to same subnet as defined by the user",
                machine.hostname)
    for slave in slaves:
        slave.links.create(maas.client.enum.LinkMode.LINK_UP,
                           force=True,
                           subnet=subnet)
        slave.tags.append("allocated")
        slave.save()
        LOGGER.info("%s: Done on %s",
                    machine.hostname,
                    slave.name)
    if 'dont_generate_mac' in iface_cfg and iface_cfg['dont_generate_mac']:
        bond_mac = None
        LOGGER.debug("%s: Not generating mac for %s",
                     machine.hostname,
                     iface_name)
    else:
        # This grabs the last 24 bits and preceding colon from the primary slave in the bond
        last_24bits = slaves[0].mac_address[-9:]
        bond_mac = BOND_PREFIX + last_24bits
        LOGGER.debug("%s: Generated %s mac of %s",
                     machine.hostname,
                     iface_name,
                     bond_mac)
    try:
        bond = machine.interfaces.create(
            name=iface_name,
            interface_type=maas.client.enum.InterfaceType.BOND,
            mac_address=bond_mac,
            parents=slaves,
            bond_mode="802.3ad",
            bond_lacp_rate="fast",
            bond_xmit_hash_policy="layer2",
            #bond_xmit_hash_policy="layer3+4",
            bond_miimon=100,
            tags=["allocated"])
    except maas.client.bones.CallError as err:
        LOGGER.critical("%s: Error on line %i, trying to create bonded interface %s error: %s",
                        machine.hostname,
                        LINE(),
                        iface_name,
                        err.content)
    return bond


def remove_unused_nics(machine: object) -> None:
    """ Removes unused interfaces from MAAS so they don't result in boot haves
    on bionic and newer with netplan
    :param machine: The Maas Machine object
    :param client: The Maas client object
    """

    LOGGER.info("%s: Removing interfaces that are not allocated (used)",
                machine.hostname)
    for interface in machine.interfaces:
        LOGGER.info("%s: Interface %s tags %s",
                    machine.hostname,
                    interface.name,
                    repr(interface.tags))
        if 'allocated' not in interface.tags:
            LOGGER.info("%s: Removing %s",
                        machine.hostname,
                        interface.name)
            interface.delete()



def configure_networking(machine: object,
                         client: object,
                         user_csv: dict,
                         profile: dict) -> None:
    """ Configures the networking for the machine baed on the machine
    profile combined with the csv provded information from the user

    :param machine: The Maas Machine Structure
    :param user_csv: the csv structure provided by the maasterblaster user
    :param client: The maas client object
    :param profile: The structure representing the machine profile from config.yml

    We have many things to do in here:
    1. parse the netcfg from the user CSV for this host
    2. walk the networking tree from the profile.
    3. If bonded,  go configure the bond and create network(s) on it
    3. If normal,  configure the interface and creat network(s) on it

    """

    if profile is None:
        LOGGER.critical("%s: Error on line %i, configure_networking(), profile passed "
                        "for %s was empty, can't continue",
                        machine.hostname,
                        LINE(),
                        machine.hostname)
        traceback.print_stack(file=sys.stdout)
        exit(1)
    # Clear out boot interface links (i.e. PXEboot info
    #if len(machine.boot_interface.links) > 0:
#    if machine.boot_interface.links:
#        machine.boot_interface.links[0].delete()
    net_profile = profile['networking']
    csv_macs = user_csv['macs']
    csv_netcfg = parse_user_netcfg(machine=machine, netcfg=user_csv['netcfg'])
    maas_subnets = client.subnets.list()
    if 'fabric' in net_profile.keys():
        fabric = net_profile['fabric']
    else:
        fabric = None
    for iface in net_profile['interfaces']:
        LOGGER.info("%s: Walking interface %s",
                    machine.hostname,
                    iface)
        iface_cfg = net_profile['interfaces'][iface]
        if 'bonded' in iface_cfg.keys() and iface_cfg['bonded']:
            bond = configure_bonded_interface(machine=machine,
                                              client=client,
                                              iface_cfg=iface_cfg,
                                              iface_name=iface,
                                              csv_netcfg=csv_netcfg,
                                              csv_macs=csv_macs,
                                              maas_subnets=maas_subnets,
                                              fabric=fabric)
            networks = iface_cfg['networks']
            for network in networks:
                netiface = networks[network]
                LOGGER.info("%s: Walking networks for bonded interface %s, network %s",
                            machine.hostname,
                            iface,
                            network)
                configure_interface(client=client,
                                    machine=machine,
                                    iface_name=iface,
                                    iface_cfg=netiface,
                                    iface_object=bond,
                                    csv_netcfg=csv_netcfg,
                                    maas_subnets=maas_subnets,
                                    fabric=fabric)

        else: # Non bonded interfaces
            LOGGER.info("%s: NON bonded interface %s",
                        machine.hostname,
                        iface)
            if 'by_mac' not in iface_cfg.keys():
                try:
                    machine_interface = machine.interfaces.get_by_name(iface)
                except maas.client.bones.CallError as err:
                    LOGGER.critical("%s: Error on line %i, trying to get interface by name %s",
                                    machine.hostname,
                                    LINE(),
                                    iface,
                                    err.content)

            if 'by_mac' in iface_cfg.keys():
                LOGGER.info("%s: Configuring %s by interface mac_addresses",
                            machine.hostname,
                            iface)
                if 'in_csv' in iface_cfg['by_mac']:
                    for mac in csv_macs.split(' '):
                        LOGGER.info("%s: Checking if %s matches",
                                    machine.hostname, mac.split(';')[1])
                        for machine_iface in machine.interfaces:
                            LOGGER.info("%s: - %s",
                                        machine.hostname,
                                        machine_iface.mac_address)
                            if ';' in mac: # Tagged mac addresses for interfaces
                                LOGGER.info("%s: multiple mac's to check against",
                                            machine.hostname)
                                try_mac = mac.split(';')
                                if try_mac[0] == iface:
                                    LOGGER.info("%s: iface %s matches an entry from CSV",
                                                machine.hostname,
                                                iface)
                                    clean_mac = colonify_mac_address(try_mac[1])
                                    if clean_mac == machine_iface.mac_address \
                                        and machine_iface.type == InterfaceType.PHYSICAL:
                                        LOGGER.info("%s: FOUND IT (%s from %s)",
                                                    machine.hostname,
                                                    clean_mac,
                                                    machine_iface.name)
                                        machine_interface = machine_iface
                                        break
                                    else:
                                        LOGGER.info("%s: Didn't match %s versus %s",
                                                    machine.hostname,
                                                    clean_mac,
                                                    machine_iface.mac_address)
                            else:
                                LOGGER.info("%s: Checking against ungrouped macs",
                                            machine.hostname)
                                clean_mac = colonify_mac_address(mac)
                                if clean_mac == machine_iface.mac_address:
                                    LOGGER.info("%s: FOUND IT (%s from %s)",
                                                machine.hostname,
                                                clean_mac,
                                                machine_iface.name)
                                    machine_interface = machine_iface
                                    break
                                else:
                                    LOGGER.info("%s: Didn't match %s versus %s",
                                                machine.hostname,
                                                clean_mac,
                                                machine_iface.mac_address)

            if machine_interface:
                LOGGER.info("%s: Found interface %s",
                            machine.hostname,
                            iface)
                networks = iface_cfg['networks']
                for network in networks:
                    netiface = networks[network]
                    LOGGER.info("%s: Walking networks for NON bonded "
                                "interface %s, network %s",
                                machine.hostname,
                                iface,
                                network)
                    configure_interface(client=client,
                                        machine=machine,
                                        iface_name=iface,
                                        iface_cfg=netiface,
                                        iface_object=machine_interface,
                                        csv_netcfg=csv_netcfg,
                                        maas_subnets=maas_subnets,
                                        fabric=fabric)


def get_subnet_from_vlan(maas_subnets: list, vlan: object) -> object:
    for subnet in maas_subnets:
        if vlan.vid == subnet.vlan.vid:
            return subnet
    raise Exception("Unable to locate subnet in vlan %i, did you mis-spell it?", vlan.vid)


def get_vlan_from_vlan_id_and_fabric(fabric: object, vid: int) -> object:
    """ Get vlan object given it's ID and fabric """
    for vlan in fabric.vlans:
        if vlan.vid == vid:
            return vlan
    raise Exception("Unable to locate vlan %i in maas for this fabric: %s"
                    ", did you mis-spell it?", vid, fabric)


def get_fabric(client: object, fabric_name: str) -> object:
    """ Get list of fabrics from MaaS """
    for fabric in client.fabrics.list():
        if fabric.name == fabric_name:
            return fabric
    raise Exception("Unable to find fabric %s, did you mis-spell it?", fabric_name)


def get_subnet(client: object,
               machine: object,
               iface_name: str,
               iface_cfg: dict,
               csv_netcfg: dict,
               maas_subnets: list,
               fabric: str) -> object:
    """ Returns the subnet object for an interface """

    if 'vlan' in iface_cfg.keys() and 'in_csv' not in iface_cfg.keys(): # Using a defined subnet
        LOGGER.info("%s: Using a defined subnet, NOT a lookup",
                    machine.hostname)
        fabric_obj = get_fabric(client, fabric)
        vlan = get_vlan_from_vlan_id_and_fabric(fabric=fabric_obj, vid=iface_cfg['vlan'])
        return get_subnet_from_vlan(maas_subnets=maas_subnets, vlan=vlan)

#    if 'subnet' in iface_cfg and 'in_csv' not in iface_cfg:
#        LOGGER.info("%s: Using a defined subnet, NOT a lookup",
#                    machine.hostname)
#        return get_maas_subnet(subnets=maas_subnets,
#                               machine=machine,
#                               subnet_name=iface_cfg['subnet'])
#
    if 'in_csv' in iface_cfg:
        found = False
        LOGGER.info("%s: Using a lookup from the user CSV",
                    machine.hostname)
        for int_netcfg in csv_netcfg:
            netcfg = csv_netcfg[int_netcfg]
            LOGGER.info("%s: iface_name is %s",
                        machine.hostname,
                        iface_name)
            LOGGER.info("%s: netcfg[name] is %s",
                        machine.hostname,
                        netcfg['name'])
            LOGGER.info("%s: netcfg[type] is %s",
                        machine.hostname,
                        netcfg['type'])
            #if netcfg['name'] == iface_name and netcfg['type'] != "vlan": # We found it
            if netcfg['name'] == iface_name: # We found it
                LOGGER.info("%s: Found the interface %s in the csv",
                            machine.hostname,
                            iface_name)
                subnet = get_maas_subnet(subnets=maas_subnets,
                                         machine=machine,
                                         ip_addr=netcfg['ip'])
                found = True
                break
        if not found:
            LOGGER.critical("%s: Error on line %i, We were unable to " \
                            "find the subnet for %s in the csv",
                            machine.hostname,
                            LINE(),
                            iface_name)
            LOGGER.critical("%s: Netcfg is \n %s",
                            machine.hostname,
                            repr(netcfg))
            traceback.print_stack(file=sys.stdout)
            exit(1)
    else:
        LOGGER.critical("%s: Error on line %i, We were unable to find " \
                        "the subnet for %s in the yaml config",
                        machine.hostname,
                        LINE(),
                        iface_name)
        traceback.print_stack(file=sys.stdout)
        exit(1)
    return subnet


def get_maas_subnet(
        subnets: list,
        machine: object,
        subnet_name: str = None,
        ip_addr: str = None) -> object:
    """ Get the maas vlanID and subnet name based on the IP passed"""
    for subnet in subnets:
        if ip_addr:
            LOGGER.debug("%s: Searching for %s in %s",
                         machine.hostname,
                         ip_addr,
                         subnet.cidr)
            if subnet.cidr == "10.0.0.0/8": # Filter this one out...
                continue
            if ipaddress.ip_address(ip_addr) in ipaddress.ip_network(subnet.cidr):
                LOGGER.info("%s: Found match for %s in %s",
                            machine.hostname,
                            ip_addr,
                            subnet.cidr)
                return subnet
        elif subnet_name:
            LOGGER.debug("%s: Searching for subnet %s",
                         machine.hostname,
                         subnet_name)
            if subnet_name == subnet.name:
                LOGGER.info("%s: Found match for %s",
                            machine.hostname,
                            subnet.name)
                return subnet

    if ip_addr:
        LOGGER.critical("%s: Error on line %i, DID NOT FIND match for %s",
                        machine.hostname,
                        LINE(),
                        ip_addr)
        traceback.print_stack(file=sys.stdout)
        exit(1)
    elif subnet_name:
        LOGGER.critical("%s: Error on line %i, DID NOT FIND match for %s",
                        machine.hostname,
                        LINE(),
                        subnet_name)
        traceback.print_stack(file=sys.stdout)
        exit(1)
    else:
        LOGGER.critical("%s: Error on line %i, Missing ip or subnet_name parameter",
                        machine.hostname,
                        LINE())
        traceback.print_stack(file=sys.stdout)
        exit(1)



def parse_user_netcfg(machine: object, netcfg: dict) -> dict:
    """ Parse the user provided network config in the CSV """
    interfaces = {}
    iface_configs = netcfg.split(' ')
    for iface in iface_configs:
        LOGGER.info("%s: Parsing \"%s\"",
                    machine.hostname,
                    iface)
        interface = {}
        ifaceinfo = iface.split(':')
        if len(ifaceinfo) != 2:
            LOGGER.critical("%s: Error on line %i, Network config in CSV " \
                            "is invalid for %s",
                            machine.hostname,
                            LINE(),
                            iface)
        interface['name'] = ifaceinfo[0]
        LOGGER.info("%s: - name: %s",
                    machine.hostname,
                    interface['name'])
        interface['ip'] = ifaceinfo[1]
        LOGGER.info("%s: - ip: %s",
                    machine.hostname,
                    interface['ip'])
        if "." in ifaceinfo[0]: # We found a vlan interface
            LOGGER.info("%s: - found vlan based on name %s",
                        machine.hostname,
                        ifaceinfo[0])
            interface['type'] = "vlan"
            tmp = ifaceinfo[0].split('.')
            interface['parent'] = tmp[0]
            LOGGER.info("%s: - interface parent %s",
                        machine.hostname,
                        interface['parent'])
            interface['vlan'] = re.sub(r'\D', '', tmp[1])
            LOGGER.info("%s: -  interface vlan is %s",
                        machine.hostname,
                        interface['vlan'])
        elif "vlan" in ifaceinfo[0]: # We found a vlan interface
            LOGGER.info("%s: - found vlan based on name %s",
                        machine.hostname,
                        ifaceinfo[0])
            interface['type'] = "vlan"
            # BAD ASSUMPTION
            interface['parent'] = "eth0"
            LOGGER.warning("%s: - bad assumption: interface parent %s",
                           machine.hostname,
                           interface['parent'])
            interface['vlan'] = re.sub(r'\D', '', ifaceinfo[0])
            LOGGER.info("%s: -  interface vlan is %s",
                        machine.hostname,
                        interface['vlan'])
        elif "br" in ifaceinfo[0]: # We found a bridge interface
            LOGGER.info("%s: - found bridge interface on name %s",
                        machine.hostname,
                        ifaceinfo[0])
            interface['type'] = "bridge"
        else:
            LOGGER.info("%s: -  interface %s is physical",
                        machine.hostname,
                        ifaceinfo[0])
            interface['type'] = "physical"
        interfaces[interface['name']] = interface

    return interfaces


def partition_disk(machine: object, disk: object, size: int = 0) -> object:
    """ Create a partition an optionally format/mount it """
    if not disk:
        LOGGER.critical("%s: Error on line %i, partition_disk, " \
                        "missing disk parameter",
                        machine.hostname,
                        LINE())
        traceback.print_stack(file=sys.stdout)
        exit(1)
    if size == 0:
        LOGGER.critical("%s: Error on line %i, partition_disk, size is zero, " \
                        "cannot create 0 byte partition",
                        machine.hostname,
                        LINE())
        traceback.print_stack(file=sys.stdout)
        exit(1)

    LOGGER.debug("Size is %i, disk.available_size is %i",
                 size,
                 disk.available_size)
    if size > (disk.available_size - BLOCK_SIZE):
        LOGGER.warning("Size %i was greater than %i-%i, adjusting size down by %i",
                       size,
                       (disk.available_size - BLOCK_SIZE),
                       BLOCK_SIZE,
                       2 * BLOCK_SIZE)
        size = disk.available_size - (2 * BLOCK_SIZE)
    else:
        LOGGER.info("Shrining partition by %i to be safe",
                    2 * BLOCK_SIZE)
        size -= (2 * BLOCK_SIZE)
    part_size = ((size // BLOCK_SIZE)) * BLOCK_SIZE
    LOGGER.debug("Partition size is %i", part_size)
    try:
        LOGGER.info("%s: Configuring partition as %i bytes on %s",
                    machine.hostname,
                    part_size,
                    disk.name)
        partition = disk.partitions.create(size=part_size)
        LOGGER.info("%s: Done", machine.hostname)
    except maas.client.bones.CallError as err:
        LOGGER.critical("%s: Error on line %i, trying to create partition " \
                        "on %s of size %i, avail: %i (%i), error(%s): %s",
                        machine.hostname,
                        LINE(),
                        disk.name,
                        part_size,
                        disk.available_size,
                        disk.available_size-part_size,
                        err.response,
                        err.content)
        traceback.print_stack(file=sys.stdout)
        exit(1)
        LOGGER.warning("%s: EXCEPTION, Configuring partition as %i bytes on %s",
                       machine.hostname,
                       part_size-512000000,
                       disk.name)
        partition = disk.partitions.create(size=part_size-512000000)
        LOGGER.info("%s: Done", machine.hostname)
    disk.save()
    disk.refresh()
    return partition


def configure_disks(machine: object, config: dict, raids: dict) -> None:
    """ Configure the Drives, based on the machine profiles specified
    in the csvline, and the details from the yaml config """
    global MD_COUNT

    swap_size = 0
    if config is None:
        LOGGER.critical("%s: Error on line %i, configure_disks(), config passed "
                        "was empty, can't continue",
                        machine.hostname,
                        LINE())
        traceback.print_stack(file=sys.stdout)
        exit(1)
    disks = find_disks_by_criteria(machine, config, raids)
    if 'bootable' in config.keys() and config['bootable']:
        LOGGER.info("%s: Setting %s to be the boot disk",
                    machine.hostname,
                    disks[0].name)
        disks[0].set_as_boot_disk()

    if 'swap_size' in config.keys():
        LOGGER.info("%s: Requested swap size is %s",
                    machine.hostname,
                    config['swap_size'])
        tmp = get_size_in_bytes(config['swap_size'], 0)
        swap_size = ((tmp // BLOCK_SIZE)) * BLOCK_SIZE
    raid_devices = []
    swap_raid_devices = []
    for disk in disks:
        # NON RAID config (single disk)
        if 'raidlevel' not in config.keys():
            LOGGER.info("%s: We are configuring a non-raid disk %s",
                        machine.hostname,
                        disk.name)
            if 'lvm' in config.keys() and config['lvm']:
                LOGGER.info("%s: Non RAID LVM config",
                            machine.hostname)
                setup_lvm(machine=machine, config=config['lvm'], devices=[disk])
            else: # Not Using LVM
                LOGGER.info("%s: Non RAID partitioned config",
                            machine.hostname)
                create_partitioned_device(machine, config, disk, disk.name)
                # ony do the first drive of a nonraid, otherwise you risk
                # duplicate mountpoint failures
                if not raids:
                    break
        else: # RAID (0,1,5,6,10)
            LOGGER.info("%s: We are configuring a RAID volume",
                        machine.hostname)
            disk.refresh()
            if swap_size > 0:
                #if 'bootable' in config.keys() and config['bootable']:
                #    make_esp_partition(machine=machine,disk=disk)

                available_size = ((disk.available_size // BLOCK_SIZE)) * BLOCK_SIZE
                LOGGER.info("%s: Creating partition of %i bytes for raid MD device on %s",
                            machine.hostname,
                            available_size-swap_size,
                            disk.name)

                raid_devices.append(partition_disk(machine=machine,
                                                   disk=disk,
                                                   size=available_size-swap_size))
                LOGGER.info("%s: Creating swap partition of %i bytes for raid MD device on %s",
                            machine.hostname,
                            swap_size,
                            disk.name)
                swap_raid_devices.append(partition_disk(machine=machine,
                                                        disk=disk,
                                                        size=swap_size))
            else:
                #if 'bootable' in config.keys() and config['bootable']:
                #    make_esp_partition(machine=machine,disk=disk)
                # Nested RAID, don't partition the children....
                if 'children' in config['match_on'].keys():
                    raid_devices.append(disk)
                else:
                    available_size = ((disk.available_size // BLOCK_SIZE)) * BLOCK_SIZE
                    LOGGER.info("%s: Creating partition of %i bytes for raid MD device on %s",
                                machine.hostname,
                                available_size,
                                disk.name)

                    raid_devices.append(partition_disk(machine=machine,
                                                       disk=disk,
                                                       size=available_size))

    if 'raidlevel' in config.keys():
        LOGGER.info("%s: Configuring RAID array",
                    machine.hostname)
        if config['raidlevel'] == 0:
            level = maas.client.enum.RaidLevel.RAID_0
        elif config['raidlevel'] == 1:
            level = maas.client.enum.RaidLevel.RAID_1
        elif config['raidlevel'] == 5:
            level = maas.client.enum.RaidLevel.RAID_5
        elif config['raidlevel'] == 6:
            level = maas.client.enum.RaidLevel.RAID_6
        elif config['raidlevel'] == 10:
            level = maas.client.enum.RaidLevel.RAID_10
        else:
            level = maas.client.enum.RaidLevel.RAID_1
        LOGGER.info("%s: Creating Raid level %i array",
                    machine.hostname,
                    config['raidlevel'])
        try:
            raid = machine.raids.create(
                name="md" + str(MD_COUNT[machine.hostname]),
                level=level,
                devices=raid_devices,
                spare_devices=[],
                )
        except maas.client.bones.CallError as err:
            LOGGER.critical("Error on line %i, trying to create raid on machine %s, error %s",
                            LINE(),
                            machine.hostname,
                            err.content)
        LOGGER.info("%s: Array created",
                    machine.hostname)
        MD_COUNT[machine.hostname] += 1
        if swap_size > 0:
            LOGGER.info("%s: Configuring swap RAID1 array",
                        machine.hostname)
            try:
                swap_raid = machine.raids.create(
                    name="md" + str(MD_COUNT[machine.hostname]),
                    level=level,
                    devices=swap_raid_devices,
                    spare_devices=[],
                    )
            except maas.client.bones.CallError as err:
                LOGGER.critical("Error on line %i, trying to create swap "
                                "raid on machine %s, error %s",
                                LINE(),
                                machine.hostname,
                                err.content)
            LOGGER.info("%s: swap RAID1 array created",
                        machine.hostname)
            MD_COUNT[machine.hostname] += 1
            swap_raid.virtual_device.format("swap")
            swap_raid.virtual_device.mount("none")
        else:
            LOGGER.info("%s: NO SWAP on this array",
                        machine.hostname)
        # If we use LVM
        if 'lvm' in config.keys() and config['lvm']:
            LOGGER.info("%s: RAID LVM config",
                        machine.hostname)
            setup_lvm(machine=machine, config=config['lvm'], devices=[raid.virtual_device])
        else: # Not Using LVM
            if 'partitions' in config.keys():
                LOGGER.info("%s: Partitioned RAID device %s",
                            machine.hostname,
                            raid.name)
                create_partitioned_device(machine, config, raid.virtual_device, raid.name)
            else:
                LOGGER.info("%s: Non-Partitioned RAID device %s",
                            machine.hostname,
                            raid.name)
                if 'add_tags' in config.keys():
                    LOGGER.info("%s: This device %s should have tags added, "
                                "calling add_tags_to_device",
                                machine.hostname,
                                raid.name)
                    add_tags_to_device(machine=machine,
                                       device=raid,
                                       config=config)
                format_and_mount(machine=machine,
                                 device=raid.virtual_device,
                                 config=config,
                                 name=raid.name)
        if 'nested' in config.keys() and config['nested']:
            LOGGER.info("%s: This raid device %s is nested (%s)",
                        machine.hostname,
                        raid.name,
                        config['parent'])
            if config['parent'] not in raids:
                raids[config['parent']] = []
            raids[config['parent']].append(raid.virtual_device)


def add_tags_to_device(machine: object, device: object, config: dict) -> None:
    """ Adds tags to a device or partition """

    if 'add_tags' in config.keys():
        LOGGER.info("%s: Device has an add_tags section",
                    machine.hostname)
        for tag in config['add_tags']:
            LOGGER.info("%s: Adding tag \"%s\" to Device",
                        machine.hostname,
                        tag)
            device.tags.append(tag)
            device.save()


def create_partitioned_device(machine: object, config: dict, device: object, name: str):
    """ Partitions a device based on the config """
    swap_size = 0
    LOGGER.info("%s: Not using LVM...",
                machine.hostname)
    # If the device is partitioned
    if 'partitions' in config.keys():
        LOGGER.info("%s: This machine has the %s device paritioned",
                    machine.hostname,
                    name)
        for part, data in config['partitions'].items():
            LOGGER.info("%s: Working on partition %s",
                        machine.hostname,
                        part)
            size = get_size_in_bytes(data['size'], device.available_size)
            LOGGER.info("%s: Creating %i byte partition",
                        machine.hostname,
                        size)
            partition = partition_disk(machine=machine,
                                       disk=device,
                                       size=size)
            LOGGER.info("%s: Partition creation complete",
                        machine.hostname)
            format_and_mount(machine=machine, device=partition, config=data, name=part)
            if 'lvm' in data.keys() and data['lvm']:
                LOGGER.info("%s: This partition is a physical volume for LVM",
                            machine.hostname)
                setup_lvm(machine=machine, config=data['lvm'], devices=[partition])

            device.refresh()

    # No partitions defined, assume one big if not bootable
    else:
        LOGGER.info("%s: This machine has the %s disk setup " \
                    "with one big partition",
                    machine.hostname,
                    name)
        # Handle case of no partitions on MD device
        if device.type == maas.client.enum.BlockDeviceType.VIRTUAL and \
        'swap_size' not in config.keys() and \
        re.search("md", device.name):
            LOGGER.info("%s: MD device, no partitioning defined",
                        machine.hostname)
            format_and_mount(machine=machine, device=partition, config=config, name=device.name)
            return

        if 'swap_size' in config.keys():
            LOGGER.info("%s: Requested swap size is %s",
                        machine.hostname,
                        config['swap_size'])
            swap_size = get_size_in_bytes(config['swap_size'], device.available_size)

        # Partition /
        partition = partition_disk(machine=machine,
                                   disk=device,
                                   size=device.available_size-swap_size)
        format_and_mount(machine=machine, device=partition, config=config, name=device.name)

        if swap_size > 0:
            LOGGER.info("%s: Creating swap parition on %s",
                        machine.hostname,
                        device.name)
            partition = partition_disk(machine=machine,
                                       disk=device,
                                       size=swap_size)
            partition.format("swap")
            partition.mount("none")
            LOGGER.info("%s: Completed creating swap parition on %s",
                        machine.hostname,
                        device.name)
            device.refresh()


# This function isn't used because maas doesn't let you set the partition type to define it
# as a true ESP
def make_esp_partition(machine: object, disk: object) -> None:
    """ For bootable partitions or devices, create the bios boot and EFI partitions """
    global ESP_COUNT

    disk.refresh()
    LOGGER.info("%s: Making 500M ESP partition of size %i",
                machine.hostname,
                get_size_in_bytes("500M", disk.available_size, False))
    partition = partition_disk(machine=machine,
                               disk=disk,
                               size=get_size_in_bytes("500M", disk.available_size, False))
    try:
        partition.format("fat32")
    except maas.client.bones.CallError as err:
        LOGGER.critical("%s: Unable to make ESP partition, error(%s)",
                        machine.hostname,
                        err.content)
        traceback.print_stack(file=sys.stdout)
        exit(1)
    if ESP_COUNT[machine.hostname] > 0:
        name = "/boot/efi" + str(ESP_COUNT[machine.hostname])
    else:
        name = "/boot/efi"
        ESP_COUNT[machine.hostname] += 1
    LOGGER.info("%s: Mounting ESP partition at %s",
                machine.hostname,
                name)
    try:
        partition.mount(name, mount_options="nofail")
    except maas.client.bones.CallError as err:
        LOGGER.critical("%s: Unable to mount ESP partition %s, error(%s)",
                        machine.hostname,
                        name,
                        err.content)
        traceback.print_stack(file=sys.stdout)
        exit(1)
        disk.set_as_boot_disk()
    disk.refresh()



def setup_lvm(machine: object, config: dict, devices: list) -> None:
    """ Sets up LVM for the specified machine at the config endpoint on
    devices array """
    if 'vg_name' not in config.keys():
        LOGGER.critical("%s: Error on line %i, Missing vg_name lvm: block, cannot continue",
                        machine.hostname,
                        LINE())
        traceback.print_stack(file=sys.stdout)
        exit(1)
    else:
        volume_group = machine.volume_groups.create(
            name=config["vg_name"],
            devices=devices)
        LOGGER.info("%s: Volume group %s created",
                    machine.hostname,
                    config["vg_name"])
        create_logical_volumes(machine=machine,
                               config=config,
                               volume_group=volume_group)


def create_logical_volumes(machine: object, config: dict, volume_group: object):
    """ Create the VG and logical volumes for this device """
    if volume_group is None or config is None:
        LOGGER.critical("%s: Error on line %i, volume_group or config is unset",
                        machine.hostname,
                        LINE())
        traceback.print_stack(file=sys.stdout)
        exit(1)

    if 'volumes' not in config.keys():
        LOGGER.critical("%s: Error on line %i, Missing 'volumes:' " \
                        "section in lvm: block, cannot continue",
                        machine.hostname,
                        LINE())
        traceback.print_stack(file=sys.stdout)
        exit(1)

    LOGGER.info("%s: This machine has one or more logical "
                "volumes on the %s Volume Group",
                machine.hostname,
                volume_group.name)
    for volume, data in config['volumes'].items():
        size = get_size_in_bytes(data['size'], volume_group.available_size)
        lv_size = ((size // BLOCK_SIZE) - 1) * BLOCK_SIZE
        if 'lv_name' not in data.keys():
            LOGGER.critical("%s: Error on line %i, Missing lv_name: key in volumes: "
                            "%s block, cannot continue",
                            machine.hostname,
                            LINE(),
                            volume)
            traceback.print_stack(file=sys.stdout)
            exit(1)
        else:
            name = data['lv_name']

        LOGGER.info("%s: Creating logical volume %s %i bytes in size",
                    machine.hostname,
                    name,
                    lv_size)
        try:
            logical_volume = volume_group.logical_volumes.create(
                size=lv_size,
                name=name)
        except maas.client.bones.CallError as err:
            LOGGER.warning("%s: Error trying to create logical volume "
                           "on %s of size %i, error(%s): %s",
                           machine.hostname,
                           volume_group.name,
                           lv_size,
                           err.response,
                           err.content)
            traceback.print_stack(file=sys.stdout)
            exit(1)
        LOGGER.info("%s: Logical Volume created",
                    machine.hostname)
        format_and_mount(machine=machine, device=logical_volume, config=data, name=name)

        volume_group.refresh()


def format_and_mount(machine: object, device: object, config: dict, name: str) -> None:
    """ Formats and configures mountpoint for device """

    if 'filesystem' in config.keys():
        LOGGER.info("%s: Setting format for this volume to %s",
                    machine.hostname,
                    config['filesystem'])
#        if 'mkfs_options' in config.keys():
#            device.format(fstype=config['filesystem'], extra_options=config['mkfs_options'])
#        else:
        device.format(config['filesystem'])
        LOGGER.info("%s: Format set for volume",
                    machine.hostname)
        if 'mountpoint' in config.keys():
            LOGGER.info("%s: Setting mountpoint for this "
                        "volume to %s",
                        machine.hostname,
                        config['mountpoint'])
            device.mount(config['mountpoint'])
            LOGGER.info("%s: Mountpoint set for volume",
                        machine.hostname)
        elif 'bootable' in config.keys() and config['bootable']:
            LOGGER.warning("%s: bootable device without mountpoint on "
                           "device %s, setting to /",
                           machine.hostname,
                           name)
            device.mount("/")
        else:
            LOGGER.warning("%s: Non bootable device without mountpoint on device %s",
                           machine.hostname,
                           name)

    # Handle edge case of no filesystem, but marked as bootable
    elif 'bootable' in config.keys() and config['bootable']:
        LOGGER.warning("%s: bootable device without filesystem designated on "
                       " device %s, Defaulting to ext4 and mountpoint "
                       "of /",
                       machine.hostname,
                       name)


#        if 'mkfs_options' in config.keys():
#            device.format(fstype="ext4", extra_options=config['mkfs_options'])
#        else:
        device.format("ext4")
        device.mount("/")
    else:
        LOGGER.warning("%s: No filesystem designated on device %s, "
                       "not formatting or mounting",
                       machine.hostname,
                       name)



def can_parallel_deploy(machines: list, config: dict, args: dict) -> bool:
    """ Checks the machien profile for each machine to see if it
    DOES NOT have disk exclusions,  if it doesn't then the group can
    be deployed in parallel, otherwise it cannot as it requires user
    validation
    """
    result = True
    for machine in machines:
        profile = config['machine_profiles'][machine['machine_profile']]
        if 'drive_exclude' in profile.keys() and profile['drive_exclude']: # Drives not to touch
            if args.force:
                result = True
            else:
                result = False

    return result


#def hammer_time(config: dict, machines: list) ->None:
#    """ If the machine data contains a hostgroup
#    check if host exists in foreman, if so, delete it and re-create"""




def deploy_machines(client: object,
                    args: dict,
                    config: dict,
                    machines: list,
                    parallelism: int) -> None:
    global MD_COUNT
    deploying_machines = []
    deploy_list = get_deployable_machines(client=client, machines=machines, config=config)

    if not deploy_list:
        LOGGER.warning("No machines are in a deployable state")
        return None

    parallel = can_parallel_deploy(machines=deploy_list, config=config, args=args)
    if parallel:
        LOGGER.info("We can build machines in parallel!")
        LOGGER.info("Deploying in parallel (up to %i) threads", parallelism)
        with ThreadPoolExecutorStackTraced(max_workers=parallelism) as executor:
            # Start the add machines...
            future_to_machine = {executor.submit(deploy_machine,
                                                 client,
                                                 args,
                                                 config,
                                                 machine): machine for machine in deploy_list}
            for future in concurrent.futures.as_completed(future_to_machine):
                row = future_to_machine[future]
                try:
                    data = future.result()
                except Exception as exc:
                    LOGGER.error("%r generated an exception: %s", row, exc)
                else:
                    deploying_machines.append(data)

    else:
        # Non parallel deployment (user interaction required)
        for machine in deploy_list:
            LOGGER.info("Deploying machine %s", machine['node'].hostname)
            data = deploy_machine(client,
                                  args,
                                  config,
                                  machine)
            deploying_machines.append(data)

    return deploying_machines



def deploy_machine(client: object, args: dict, config: dict, req_machine: dict) -> object:
    """ Heavy Lifter
    We need to do many things here:
    1. Ensure the machine is in a "Ready" State
    2. Ensure the machine profile handlers are available
    3. Get the machine json
    4. Setup Disk configuration
    5. Setup Network Configuration
    6. Run custom scripts to "fix" any default Maas-ism's we need like
       routes or gateways done a specific way
    7. Initiate the delpoyment
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    LOGGER.info("%s: deploy_machine", req_machine['node'].hostname)
    if 'node' not in req_machine:
        LOGGER.warning("Possibile commissioning failure for machine " \
                       "Node information is missing, skipping it")
        LOGGER.warning("Raw Machine info: %r", req_machine)
        return None

    LOGGER.info("%s: Querying MaaS for machine details",
                req_machine['node'].hostname)
    machine = client.machines.get(system_id=req_machine['system_id'])
    if 'foreman_hostgroup_id' in req_machine:
        LOGGER.info("Getting Foreman Client")
        foremanClient = ForemanClient(args)
        tmp, result = foremanClient.get_host(machine.hostname + '.' + req_machine['domain'])

        if not result: # error, host doesn't exist
            foremanClient.pair_host(machine.hostname + '.' + req_machine['domain'],
                                    req_machine['foreman_hostgroup_id'])
        elif tmp['name'] == machine.hostname + '.' + req_machine['domain']:
            LOGGER.info("Host %s already existst in puppet", tmp['name'])
            if tmp['hostgroup_id'] == int(req_machine['foreman_hostgroup_id']):
                LOGGER.info("Host %s already exists in puppet and is in the correct hostgroup",
                            machine.hostname + '.' + req_machine['domain'])
            else:
                LOGGER.warning("Host %s is not in the corect hostgroup, "
                               "it is in %i (%s), it should be in %s",
                               tmp['name'],
                               tmp['hostgroup_id'],
                               tmp['hostgroup_title'],
                               req_machine['foreman_hostgroup_id'])
                foremanClient.update_host_hostgroup(tmp['name'],
                                                    req_machine['foreman_hostgroup_id'])
    cleanup_machine(machine)
    # Get an easier to manage anchor point
    profile = config['machine_profiles'][req_machine['machine_profile']]
    # Build all raid arrays
    MD_COUNT[req_machine['node'].hostname] = 0
    ESP_COUNT[req_machine['node'].hostname] = 0
    if 'drive_exclude' in profile.keys() and profile['drive_exclude']: # Drives not to touch
        for exclude in profile['drive_exclude']:
            count = exclude_disks_by_criteria(machine,
                                              profile['drive_exclude'][exclude])
            if 'exclude_count' in profile['drive_exclude'][exclude]:
                if count < profile['drive_exclude'][exclude]['exclude_count']:
                    LOGGER.error("%s: Drive exclusion count (%i) IS NOT "
                                 "GREATER OR EQUAL to machine profile requirement (%i), "
                                 "Aborting!",
                                 req_machine['node'].hostname,
                                 count,
                                 profile['drive_exclude'][exclude]['exclude_count'])
                    exit(1)
    machine.refresh()
    raids = {}
    if 'raids' in profile.keys() and profile['raids']: # RAID disk configs
        for raid in profile['raids']:
            configure_disks(machine,
                            profile['raids'][raid], raids)
    machine.refresh()
    if 'nonraids' in profile.keys() and profile['nonraids']:  # Non raid config
        for nonraid in profile['nonraids']:
            configure_disks(machine,
                            profile['nonraids'][nonraid], None)

    configure_networking(machine=machine,
                         client=client,
                         user_csv=req_machine,
                         profile=profile)

    remove_unused_nics(machine=machine)

    user_data = build_user_data(profile)
    if 'drive_exclude' in profile.keys() \
    and profile['drive_exclude'] \
    and not args.force: # Must prompt
        if not prompt_user(question="This has drive exclusions, " \
                           "if you wish to skip this add the" \
                           "\"--force\" CLI option otherwise check the GUI " \
                           "that everything was done correctly as " \
                           "deployment cannot be undone once you hit 'y' "):
            LOGGER.critical("You answered in the negative to deploy %s",
                            machine.hostname)
            exit(1)

    try:
        machine.deploy(distro_series=profile['os'],
                       user_data=user_data,
                       hwe_kernel=profile['kernel'])

    except maas.client.bones.CallError as err:
        LOGGER.warning("%s: Error on line %i, Deployment failed:, error: %s",
                       machine.hostname,
                       LINE(),
                       err.content)
    LOGGER.info("%s: Deployment started",
                machine.hostname)

    return machine

def remove_noncommissionable_from_wanted(wanted: list, to_remove: list) -> Tuple[list, list]:
    """ Removed non commissionable machines from the wanted list
    Walks the wanted list and removes any from the remove list
    and returns the shortened list

    :param wanted:    list of machines wanted by the user (from their CSV)
    :param to_remove: list of machines in READY state within MAAS
    :type  wanted:    list
    :type  to_remove: list
    :returns:         two lists
    """
    tmp_result = wanted.copy()
    removed = []
    for want in wanted:
        for canidate in to_remove:
            if want['shortname'] == canidate.hostname:
                if canidate.status not in [
                        NodeStatus.READY,
                        NodeStatus.NEW]:
                    tmp_result.remove(want)
                    removed.append(want)

    return tmp_result, removed


def remove_known_from_wanted(wanted: list, to_remove: list) -> Tuple[list, list]:
    """ Removed known machines from the wanted list
    Walks the wanted list and removes any from the remove list
    and returns the shortened list

    :param wanted:    list of machines wanted by the user (from their CSV)
    :param to_remove: list of machines in NEW state within MAAS
    :type  wanted:    list
    :type  to_remove: list
    :returns:         two lists
    """
    tmp_result = wanted.copy()
    removed = []
    for want in wanted:
        for canidate in to_remove:
            if want['shortname'] == canidate['node'].hostname:
                tmp_result.remove(want)
                removed.append(want)

    return tmp_result, removed


def prompt_user(question: str) -> bool:
    """ Prompt user for y/n response, returning true if the repsonse is yes"""
    answer = input(question)
    if answer.upper() != 'Y':
        return False
    else:
        return True


def main():
    """ Where the action happens """
    args = parse_args()
    yaml_str = ""
    # Assemble all the yaml snippets into one big blob and load/parse
    for root, dirs, files in os.walk(os.path.dirname(__file__) + "/config", True):
        dirs.sort()
        files.sort()
        #print(dirs)
        #print(files)
        for f in files:
            if ".yml" in f:
                #LOGGER.info("Reading file %s: ", os.path.join(root,f))
                with open(os.path.join(root, f)) as snippet:
                    try:
                        yaml_str += snippet.read()
                    except Exception as exc:
                        LOGGER.error("Parse error on %r, generated an "
                                     "exception: %s",
                                     os.path.join(root, f),
                                     exc)

    cfg = yaml.load(yaml_str, Loader=yaml.SafeLoader)

    if args.list_profiles:
        LOGGER.info("Listing Profiles")
        for section in cfg['machine_profiles']:
            print(section)
        exit(1)

    if args.show_profile:
        LOGGER.info("Showing Profile: %s", args.show_profile)
        print(yaml.dump(cfg['machine_profiles'][args.show_profile], default_flow_style=False))
        exit(1)

    if args.input_csv:
        LOGGER.info("Parsing CSV: %s", args.input_csv)
        wanted = load_csv(config=cfg, file=args.input_csv, limit=args.limit)
        if len(wanted) == 0:
            LOGGER.info("Nothing to do, did you limit filter everything out?")
            exit(1)

    if args.commission \
    or args.deploy \
    or args.release \
    or args.abort \
    or args.unlock \
    or args.lock \
    or args.delete:
        if not args.input_csv:
            LOGGER.error("Need to specify -i <input_csv> for commissioning,"
                         " deployment, release, abort, delete, lock or unlock")
            exit(1)

        client = maas_authenticate(args=args)
        LOGGER.info("Querying MAAS for machines to see if it knows about the "
                    "%i instances specified in the CSV file (%s)",
                    len(wanted),
                    args.input_csv)

    if args.abort:
        if not args.force:
            LOGGER.error("Unable to abort without --force")
            exit(-1)
        else:
            LOGGER.info("Aborting hosts")
            abort_machines(client=client,
                           machines_to_abort=wanted,
                           parallelism=args.parallelism)

    if args.unlock:
        if not args.force:
            LOGGER.error("Unable to unlock without --force")
            exit(-1)
        else:
            LOGGER.info("Unlocking hosts")
            unlock_machines(client=client,
                            machines_to_unlock=wanted,
                            parallelism=args.parallelism)

    if args.lock:
        LOGGER.info("Locking hosts")
        lock_machines(client=client,
                      machines_to_lock=wanted,
                      parallelism=args.parallelism)

    if args.release:
        if not args.force:
            LOGGER.error("Unable to release without --force")
            exit(-1)
        else:
            LOGGER.info("Releasing hosts")
            release_machines(client=client,
                             args=args,
                             to_release=wanted,
                             parallelism=args.parallelism)

    if args.delete:
        if not args.force:
            LOGGER.error("Unable to delete without --force")
            exit(-1)
        else:
            LOGGER.info("Deleting hosts")
            delete_machines(client=client,
                            machines_to_delete=wanted,
                            parallelism=args.parallelism)

    if args.commission:
        """ We have several conditions to handle:
        1. None of the requested machines are known to maas and should all be added
        2. Some are known to maas and are in NEW state (they can be commissioned)
        3. Some are in maas and are NOT in new state and thus cannot be commissioned
        """
        LOGGER.info("Warning this step is currently slow, please be patient")
        for instance in wanted:
            LOGGER.info("    " + instance['shortname'] + "." + instance['domain'])
        new_machines = add_machines(client=client,
                                    machines_to_add=wanted,
                                    parallelism=args.parallelism,
                                    skip_custom_commission=args.skip_custom
                                   )
        if new_machines == None:
            exit(1)

        machines = commission_machines(client=client,
                                       new_machines=new_machines,
                                       skip_custom_commission=args.skip_custom)
        power_off_machines(machines=machines)
    if args.deploy:
        LOGGER.info("Deployment requested")
        # Requery to update wanted
        LOGGER.info("Deployment initiated on nodes")
        deploying_machines = deploy_machines(client=client,
                                             args=args,
                                             config=cfg,
                                             machines=wanted,
                                             parallelism=args.parallelism)
        monitor_deployment(client=client,
                           machines=deploying_machines)
        LOGGER.info("Locking hosts")
        lock_machines(client=client,
                      machines_to_lock=wanted,
                      parallelism=args.parallelism)


if __name__ == "__main__":
    main()
