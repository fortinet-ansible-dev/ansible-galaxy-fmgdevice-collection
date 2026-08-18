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
module: fmgd_system_ddns
short_description: Configure DDNS.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_ddns:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      addr_type:
        aliases: ['addr-type']
        type: str
        description: Address type of interface address in DDNS update.
        choices: ['ipv4', 'ipv6']
      bound_ip:
        aliases: ['bound-ip']
        type: str
        description: Bound ip.
      clear_text:
        aliases: ['clear-text']
        type: str
        description: Enable/disable use of clear text connections.
        choices: ['disable', 'enable']
      ddns_auth:
        aliases: ['ddns-auth']
        type: str
        description: Enable/disable TSIG authentication for your DDNS server.
        choices: ['disable', 'tsig']
      ddns_domain:
        aliases: ['ddns-domain']
        type: str
        description: Your fully qualified domain name.
      ddns_key:
        aliases: ['ddns-key']
        type: list
        elements: str
        description: DDNS update key
      ddns_keyname:
        aliases: ['ddns-keyname']
        type: str
        description: DDNS update key name.
      ddns_password:
        aliases: ['ddns-password']
        type: list
        elements: str
        description: DDNS password.
      ddns_server:
        aliases: ['ddns-server']
        type: str
        description: Select a DDNS service provider.
        choices: ['dhs.org', 'dyndns.org', 'dyns.net', 'tzo.com', 'ods.org', 'vavic.com',
                  'now.net.cn', 'dipdns.net', 'easydns.com', 'genericDDNS', 'FortiGuardDDNS',
                  'noip.com']
      ddns_server_addr:
        aliases: ['ddns-server-addr']
        type: list
        elements: str
        description: Generic DDNS server IP/FQDN list.
      ddns_sn:
        aliases: ['ddns-sn']
        type: str
        description: DDNS Serial Number.
      ddns_ttl:
        aliases: ['ddns-ttl']
        type: int
        description: Time-to-live for DDNS packets.
      ddns_username:
        aliases: ['ddns-username']
        type: str
        description: DDNS user name.
      ddns_zone:
        aliases: ['ddns-zone']
        type: str
        description: Zone of your domain name
      ddnsid:
        type: int
        description: DDNS ID.
      monitor_interface:
        aliases: ['monitor-interface']
        type: list
        elements: str
        description: Monitored interface.
      server_type:
        aliases: ['server-type']
        type: str
        description: Address type of the DDNS server.
        choices: ['ipv4', 'ipv6']
      ssl_certificate:
        aliases: ['ssl-certificate']
        type: list
        elements: str
        description: Name of local certificate for SSL connections.
      update_interval:
        aliases: ['update-interval']
        type: int
        description: DDNS update interval
      use_public_ip:
        aliases: ['use-public-ip']
        type: str
        description: Enable/disable use of public IP address.
        choices: ['disable', 'enable']
      ddns_server_ip:
        aliases: ['ddns-server-ip']
        type: str
        description: Generic DDNS server IP.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure DDNS.
      fortinet.fmgdevice.fmgd_system_ddns:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        system_ddns:
          # addr_type: <value in [ipv4, ipv6]>
          # bound_ip: <string>
          # clear_text: <value in [disable, enable]>
          # ddns_auth: <value in [disable, tsig]>
          # ddns_domain: <string>
          # ddns_key: <list or string>
          # ddns_keyname: <string>
          # ddns_password: <list or string>
          # ddns_server: <value in [dhs.org, dyndns.org, dyns.net, ...]>
          # ddns_server_addr: <list or string>
          # ddns_sn: <string>
          # ddns_ttl: <integer>
          # ddns_username: <string>
          # ddns_zone: <string>
          # ddnsid: <integer>
          # monitor_interface: <list or string>
          # server_type: <value in [ipv4, ipv6]>
          # ssl_certificate: <list or string>
          # update_interval: <integer>
          # use_public_ip: <value in [disable, enable]>
          # ddns_server_ip: <string>
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
        '/pm/config/device/{device}/global/system/ddns'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_ddns': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'addr-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                'bound-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'clear-text': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ddns-auth': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'tsig'], 'type': 'str'},
                'ddns-domain': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'ddns-key': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'ddns-keyname': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'str'},
                'ddns-password': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'ddns-server': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': [
                        'dhs.org', 'dyndns.org', 'dyns.net', 'tzo.com', 'ods.org', 'vavic.com', 'now.net.cn', 'dipdns.net', 'easydns.com', 'genericDDNS',
                        'FortiGuardDDNS', 'noip.com'
                    ],
                    'type': 'str'
                },
                'ddns-server-addr': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ddns-sn': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'ddns-ttl': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'ddns-username': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'ddns-zone': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'ddnsid': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'monitor-interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'server-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                'ssl-certificate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'update-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'use-public-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ddns-server-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_ddns'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
