#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgd_system_dhcp_server
short_description: Configure DHCP servers.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
version_added: "1.1.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    device:
        description: The parameter (device) in requested url.
        type: str
        required: true
    vdom:
        description: The parameter (vdom) in requested url.
        type: str
        required: true
    system_dhcp_server:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auto_configuration:
                aliases: ['auto-configuration']
                type: str
                description: Enable/disable auto configuration.
                choices:
                    - 'disable'
                    - 'enable'
            auto_managed_status:
                aliases: ['auto-managed-status']
                type: str
                description: Enable/disable use of this DHCP server once this interface has been assigned an IP address from FortiIPAM.
                choices:
                    - 'disable'
                    - 'enable'
            conflicted_ip_timeout:
                aliases: ['conflicted-ip-timeout']
                type: int
                description: Time in seconds to wait after a conflicted IP address is removed from the DHCP range before it can be reused.
            ddns_auth:
                aliases: ['ddns-auth']
                type: str
                description: DDNS authentication mode.
                choices:
                    - 'disable'
                    - 'tsig'
            ddns_key:
                aliases: ['ddns-key']
                type: list
                elements: str
                description: DDNS update key
            ddns_keyname:
                aliases: ['ddns-keyname']
                type: str
                description: DDNS update key name.
            ddns_server_ip:
                aliases: ['ddns-server-ip']
                type: str
                description:
                    - Support meta variable
                    - DDNS server IP.
            ddns_ttl:
                aliases: ['ddns-ttl']
                type: int
                description: TTL.
            ddns_update:
                aliases: ['ddns-update']
                type: str
                description: Enable/disable DDNS update for DHCP.
                choices:
                    - 'disable'
                    - 'enable'
            ddns_update_override:
                aliases: ['ddns-update-override']
                type: str
                description: Enable/disable DDNS update override for DHCP.
                choices:
                    - 'disable'
                    - 'enable'
            ddns_zone:
                aliases: ['ddns-zone']
                type: str
                description: Zone of your domain name
            default_gateway:
                aliases: ['default-gateway']
                type: str
                description:
                    - Support meta variable
                    - Default gateway IP address assigned by the DHCP server.
            dhcp_settings_from_fortiipam:
                aliases: ['dhcp-settings-from-fortiipam']
                type: str
                description: Enable/disable populating of DHCP server settings from FortiIPAM.
                choices:
                    - 'disable'
                    - 'enable'
            dns_server1:
                aliases: ['dns-server1']
                type: str
                description:
                    - Support meta variable
                    - DNS server 1.
            dns_server2:
                aliases: ['dns-server2']
                type: str
                description:
                    - Support meta variable
                    - DNS server 2.
            dns_server3:
                aliases: ['dns-server3']
                type: str
                description:
                    - Support meta variable
                    - DNS server 3.
            dns_server4:
                aliases: ['dns-server4']
                type: str
                description:
                    - Support meta variable
                    - DNS server 4.
            dns_service:
                aliases: ['dns-service']
                type: str
                description: Options for assigning DNS servers to DHCP clients.
                choices:
                    - 'default'
                    - 'specify'
                    - 'local'
            domain:
                type: str
                description: Domain name suffix for the IP addresses that the DHCP server assigns to clients.
            exclude_range:
                aliases: ['exclude-range']
                type: list
                elements: dict
                description: Exclude range.
                suboptions:
                    end_ip:
                        aliases: ['end-ip']
                        type: str
                        description: End of IP range.
                    id:
                        type: int
                        description: ID.
                    lease_time:
                        aliases: ['lease-time']
                        type: int
                        description: Lease time in seconds, 0 means default lease time.
                    start_ip:
                        aliases: ['start-ip']
                        type: str
                        description: Start of IP range.
                    uci_match:
                        aliases: ['uci-match']
                        type: str
                        description: Enable/disable user class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    uci_string:
                        aliases: ['uci-string']
                        type: list
                        elements: str
                        description: One or more UCI strings in quotes separated by spaces.
                    vci_match:
                        aliases: ['vci-match']
                        type: str
                        description: Enable/disable vendor class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    vci_string:
                        aliases: ['vci-string']
                        type: list
                        elements: str
                        description: One or more VCI strings in quotes separated by spaces.
            filename:
                type: str
                description: Name of the boot file on the TFTP server.
            forticlient_on_net_status:
                aliases: ['forticlient-on-net-status']
                type: str
                description: Enable/disable FortiClient-On-Net service for this DHCP server.
                choices:
                    - 'disable'
                    - 'enable'
            id:
                type: int
                description: ID.
                required: true
            interface:
                type: list
                elements: str
                description: DHCP server can assign IP configurations to clients connected to this interface.
            ip_mode:
                aliases: ['ip-mode']
                type: str
                description: Method used to assign client IP.
                choices:
                    - 'range'
                    - 'usrgrp'
            ip_range:
                aliases: ['ip-range']
                type: list
                elements: dict
                description: Ip range.
                suboptions:
                    end_ip:
                        aliases: ['end-ip']
                        type: str
                        description:
                            - Support meta variable
                            - End of IP range.
                    id:
                        type: int
                        description: ID.
                    lease_time:
                        aliases: ['lease-time']
                        type: int
                        description: Lease time in seconds, 0 means default lease time.
                    start_ip:
                        aliases: ['start-ip']
                        type: str
                        description:
                            - Support meta variable
                            - Start of IP range.
                    uci_match:
                        aliases: ['uci-match']
                        type: str
                        description: Enable/disable user class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    uci_string:
                        aliases: ['uci-string']
                        type: list
                        elements: str
                        description: One or more UCI strings in quotes separated by spaces.
                    vci_match:
                        aliases: ['vci-match']
                        type: str
                        description: Enable/disable vendor class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    vci_string:
                        aliases: ['vci-string']
                        type: list
                        elements: str
                        description: One or more VCI strings in quotes separated by spaces.
            ipsec_lease_hold:
                aliases: ['ipsec-lease-hold']
                type: int
                description: DHCP over IPsec leases expire this many seconds after tunnel down
            lease_time:
                aliases: ['lease-time']
                type: int
                description: Lease time in seconds, 0 means unlimited.
            mac_acl_default_action:
                aliases: ['mac-acl-default-action']
                type: str
                description: MAC access control default action
                choices:
                    - 'assign'
                    - 'block'
            netmask:
                type: str
                description:
                    - Support meta variable
                    - Netmask assigned by the DHCP server.
            next_server:
                aliases: ['next-server']
                type: str
                description:
                    - Support meta variable
                    - IP address of a server
            ntp_server1:
                aliases: ['ntp-server1']
                type: str
                description:
                    - Support meta variable
                    - NTP server 1.
            ntp_server2:
                aliases: ['ntp-server2']
                type: str
                description:
                    - Support meta variable
                    - NTP server 2.
            ntp_server3:
                aliases: ['ntp-server3']
                type: str
                description:
                    - Support meta variable
                    - NTP server 3.
            ntp_service:
                aliases: ['ntp-service']
                type: str
                description: Options for assigning Network Time Protocol
                choices:
                    - 'default'
                    - 'specify'
                    - 'local'
            options:
                type: list
                elements: dict
                description: Options.
                suboptions:
                    code:
                        type: int
                        description: DHCP option code.
                    id:
                        type: int
                        description: ID.
                    ip:
                        type: list
                        elements: str
                        description: DHCP option IPs.
                    type:
                        type: str
                        description: DHCP option type.
                        choices:
                            - 'hex'
                            - 'string'
                            - 'ip'
                            - 'fqdn'
                    uci_match:
                        aliases: ['uci-match']
                        type: str
                        description: Enable/disable user class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    uci_string:
                        aliases: ['uci-string']
                        type: list
                        elements: str
                        description: One or more UCI strings in quotes separated by spaces.
                    value:
                        type: str
                        description: DHCP option value.
                    vci_match:
                        aliases: ['vci-match']
                        type: str
                        description: Enable/disable vendor class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    vci_string:
                        aliases: ['vci-string']
                        type: list
                        elements: str
                        description: One or more VCI strings in quotes separated by spaces.
            reserved_address:
                aliases: ['reserved-address']
                type: list
                elements: dict
                description: Reserved address.
                suboptions:
                    action:
                        type: str
                        description: Options for the DHCP server to configure the client with the reserved MAC address.
                        choices:
                            - 'assign'
                            - 'block'
                            - 'reserved'
                    circuit_id:
                        aliases: ['circuit-id']
                        type: str
                        description: Option 82 circuit-ID of the client that will get the reserved IP address.
                    circuit_id_type:
                        aliases: ['circuit-id-type']
                        type: str
                        description: DHCP option type.
                        choices:
                            - 'hex'
                            - 'string'
                    description:
                        type: str
                        description: Description.
                    id:
                        type: int
                        description: ID.
                    ip:
                        type: str
                        description: IP address to be reserved for the MAC address.
                    mac:
                        type: str
                        description: MAC address of the client that will get the reserved IP address.
                    remote_id:
                        aliases: ['remote-id']
                        type: str
                        description: Option 82 remote-ID of the client that will get the reserved IP address.
                    remote_id_type:
                        aliases: ['remote-id-type']
                        type: str
                        description: DHCP option type.
                        choices:
                            - 'hex'
                            - 'string'
                    type:
                        type: str
                        description: DHCP reserved-address type.
                        choices:
                            - 'mac'
                            - 'option82'
            server_type:
                aliases: ['server-type']
                type: str
                description: DHCP server can be a normal DHCP server or an IPsec DHCP server.
                choices:
                    - 'regular'
                    - 'ipsec'
            status:
                type: str
                description: Enable/disable this DHCP configuration.
                choices:
                    - 'disable'
                    - 'enable'
            tftp_server:
                aliases: ['tftp-server']
                type: list
                elements: str
                description: One or more hostnames or IP addresses of the TFTP servers in quotes separated by spaces.
            timezone:
                type: str
                description: Select the time zone to be assigned to DHCP clients.
                choices:
                    - '00'
                    - '01'
                    - '02'
                    - '03'
                    - '04'
                    - '05'
                    - '81'
                    - '06'
                    - '07'
                    - '08'
                    - '09'
                    - '10'
                    - '11'
                    - '12'
                    - '13'
                    - '74'
                    - '14'
                    - '77'
                    - '15'
                    - '16'
                    - '17'
                    - '18'
                    - '19'
                    - '20'
                    - '75'
                    - '21'
                    - '22'
                    - '23'
                    - '24'
                    - '80'
                    - '79'
                    - '25'
                    - '26'
                    - '27'
                    - '28'
                    - '78'
                    - '29'
                    - '30'
                    - '31'
                    - '32'
                    - '33'
                    - '34'
                    - '35'
                    - '36'
                    - '37'
                    - '38'
                    - '40'
                    - '41'
                    - '42'
                    - '43'
                    - '39'
                    - '44'
                    - '46'
                    - '47'
                    - '51'
                    - '48'
                    - '45'
                    - '49'
                    - '50'
                    - '52'
                    - '53'
                    - '54'
                    - '55'
                    - '56'
                    - '57'
                    - '58'
                    - '59'
                    - '60'
                    - '62'
                    - '63'
                    - '61'
                    - '64'
                    - '65'
                    - '66'
                    - '67'
                    - '68'
                    - '69'
                    - '70'
                    - '71'
                    - '72'
                    - '82'
                    - '73'
                    - '76'
                    - '83'
                    - '84'
                    - '85'
                    - '86'
                    - '87'
            timezone_option:
                aliases: ['timezone-option']
                type: str
                description: Options for the DHCP server to set the clients time zone.
                choices:
                    - 'disable'
                    - 'default'
                    - 'specify'
            vci_match:
                aliases: ['vci-match']
                type: str
                description: Enable/disable vendor class identifier
                choices:
                    - 'disable'
                    - 'enable'
            vci_string:
                aliases: ['vci-string']
                type: list
                elements: str
                description: One or more VCI strings in quotes separated by spaces.
            wifi_ac_service:
                aliases: ['wifi-ac-service']
                type: str
                description: Options for assigning WiFi access controllers to DHCP clients.
                choices:
                    - 'specify'
                    - 'local'
            wifi_ac1:
                aliases: ['wifi-ac1']
                type: str
                description: WiFi Access Controller 1 IP address
            wifi_ac2:
                aliases: ['wifi-ac2']
                type: str
                description: WiFi Access Controller 2 IP address
            wifi_ac3:
                aliases: ['wifi-ac3']
                type: str
                description: WiFi Access Controller 3 IP address
            wins_server1:
                aliases: ['wins-server1']
                type: str
                description: WINS server 1.
            wins_server2:
                aliases: ['wins-server2']
                type: str
                description: WINS server 2.
            relay_agent:
                aliases: ['relay-agent']
                type: str
                description: Relay agent IP.
            shared_subnet:
                aliases: ['shared-subnet']
                type: str
                description: Enable/disable shared subnet.
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure DHCP servers.
      fortinet.fmgdevice.fmgd_system_dhcp_server:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        system_dhcp_server:
          id: 0 # Required variable, integer
          # auto_configuration: <value in [disable, enable]>
          # auto_managed_status: <value in [disable, enable]>
          # conflicted_ip_timeout: <integer>
          # ddns_auth: <value in [disable, tsig]>
          # ddns_key: <list or string>
          # ddns_keyname: <string>
          # ddns_server_ip: <string>
          # ddns_ttl: <integer>
          # ddns_update: <value in [disable, enable]>
          # ddns_update_override: <value in [disable, enable]>
          # ddns_zone: <string>
          # default_gateway: <string>
          # dhcp_settings_from_fortiipam: <value in [disable, enable]>
          # dns_server1: <string>
          # dns_server2: <string>
          # dns_server3: <string>
          # dns_server4: <string>
          # dns_service: <value in [default, specify, local]>
          # domain: <string>
          # exclude_range:
          #   - end_ip: <string>
          #     id: <integer>
          #     lease_time: <integer>
          #     start_ip: <string>
          #     uci_match: <value in [disable, enable]>
          #     uci_string: <list or string>
          #     vci_match: <value in [disable, enable]>
          #     vci_string: <list or string>
          # filename: <string>
          # forticlient_on_net_status: <value in [disable, enable]>
          # interface: <list or string>
          # ip_mode: <value in [range, usrgrp]>
          # ip_range:
          #   - end_ip: <string>
          #     id: <integer>
          #     lease_time: <integer>
          #     start_ip: <string>
          #     uci_match: <value in [disable, enable]>
          #     uci_string: <list or string>
          #     vci_match: <value in [disable, enable]>
          #     vci_string: <list or string>
          # ipsec_lease_hold: <integer>
          # lease_time: <integer>
          # mac_acl_default_action: <value in [assign, block]>
          # netmask: <string>
          # next_server: <string>
          # ntp_server1: <string>
          # ntp_server2: <string>
          # ntp_server3: <string>
          # ntp_service: <value in [default, specify, local]>
          # options:
          #   - code: <integer>
          #     id: <integer>
          #     ip: <list or string>
          #     type: <value in [hex, string, ip, ...]>
          #     uci_match: <value in [disable, enable]>
          #     uci_string: <list or string>
          #     value: <string>
          #     vci_match: <value in [disable, enable]>
          #     vci_string: <list or string>
          # reserved_address:
          #   - action: <value in [assign, block, reserved]>
          #     circuit_id: <string>
          #     circuit_id_type: <value in [hex, string]>
          #     description: <string>
          #     id: <integer>
          #     ip: <string>
          #     mac: <string>
          #     remote_id: <string>
          #     remote_id_type: <value in [hex, string]>
          #     type: <value in [mac, option82]>
          # server_type: <value in [regular, ipsec]>
          # status: <value in [disable, enable]>
          # tftp_server: <list or string>
          # timezone: <value in [00, 01, 02, ...]>
          # timezone_option: <value in [disable, default, specify]>
          # vci_match: <value in [disable, enable]>
          # vci_string: <list or string>
          # wifi_ac_service: <value in [specify, local]>
          # wifi_ac1: <string>
          # wifi_ac2: <string>
          # wifi_ac3: <string>
          # wins_server1: <string>
          # wins_server2: <string>
          # relay_agent: <string>
          # shared_subnet: <value in [disable, enable]>
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fmgdevice.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fmgdevice.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/device/{device}/vdom/{vdom}/system/dhcp/server'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'id'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_dhcp_server': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'auto-configuration': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auto-managed-status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'conflicted-ip-timeout': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'ddns-auth': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'tsig'], 'type': 'str'},
                'ddns-key': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'ddns-keyname': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'str'},
                'ddns-server-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'ddns-ttl': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'ddns-update': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ddns-update-override': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ddns-zone': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'default-gateway': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'dhcp-settings-from-fortiipam': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dns-server1': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'dns-server2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'dns-server3': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'dns-server4': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'dns-service': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['default', 'specify', 'local'], 'type': 'str'},
                'domain': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'exclude-range': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'end-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'lease-time': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'start-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'uci-match': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'uci-string': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'vci-match': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vci-string': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'filename': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'forticlient-on-net-status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'interface': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ip-mode': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['range', 'usrgrp'], 'type': 'str'},
                'ip-range': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'end-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'lease-time': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'start-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'uci-match': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'uci-string': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'vci-match': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vci-string': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'ipsec-lease-hold': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'lease-time': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'mac-acl-default-action': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['assign', 'block'], 'type': 'str'},
                'netmask': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'next-server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'ntp-server1': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'ntp-server2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'ntp-server3': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'ntp-service': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['default', 'specify', 'local'], 'type': 'str'},
                'options': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'code': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['hex', 'string', 'ip', 'fqdn'], 'type': 'str'},
                        'uci-match': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'uci-string': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'value': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'vci-match': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vci-string': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'reserved-address': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['assign', 'block', 'reserved'], 'type': 'str'},
                        'circuit-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'circuit-id-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['hex', 'string'], 'type': 'str'},
                        'description': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'mac': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'remote-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'remote-id-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['hex', 'string'], 'type': 'str'},
                        'type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['mac', 'option82'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'server-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['regular', 'ipsec'], 'type': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tftp-server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'timezone': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': [
                        '00', '01', '02', '03', '04', '05', '81', '06', '07', '08', '09', '10', '11', '12', '13', '74', '14', '77', '15', '16', '17',
                        '18', '19', '20', '75', '21', '22', '23', '24', '80', '79', '25', '26', '27', '28', '78', '29', '30', '31', '32', '33', '34',
                        '35', '36', '37', '38', '40', '41', '42', '43', '39', '44', '46', '47', '51', '48', '45', '49', '50', '52', '53', '54', '55',
                        '56', '57', '58', '59', '60', '62', '63', '61', '64', '65', '66', '67', '68', '69', '70', '71', '72', '82', '73', '76', '83',
                        '84', '85', '86', '87'
                    ],
                    'type': 'str'
                },
                'timezone-option': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'default', 'specify'], 'type': 'str'},
                'vci-match': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vci-string': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'wifi-ac-service': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['specify', 'local'], 'type': 'str'},
                'wifi-ac1': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'wifi-ac2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'wifi-ac3': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'wins-server1': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'wins-server2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'relay-agent': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'shared-subnet': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_dhcp_server'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
