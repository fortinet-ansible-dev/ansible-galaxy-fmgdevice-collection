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
module: fmgd_system_centralmanagement_serverlist
short_description: Additional severs that the FortiGate can use for updates
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_centralmanagement_serverlist:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      addr_type:
        aliases: ['addr-type']
        type: str
        description: Indicate whether the FortiGate communicates with the override server using an IPv4 address, an IPv6 address or a FQDN.
        choices: ['fqdn', 'ipv4', 'ipv6']
      fqdn:
        type: str
        description: FQDN address of override server.
      id:
        type: int
        description: ID.
        required: true
      server_address:
        aliases: ['server-address']
        type: str
        description: IPv4 address of override server.
      server_address6:
        aliases: ['server-address6']
        type: str
        description: IPv6 address of override server.
      server_type:
        aliases: ['server-type']
        type: list
        elements: str
        description: FortiGuard service type.
        choices: ['update', 'rating', 'iot-query', 'iot-collect', 'vpatch-query', 'iotv-query']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Additional severs that the FortiGate can use for updates
      fortinet.fmgdevice.fmgd_system_centralmanagement_serverlist:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        system_centralmanagement_serverlist:
          id: 0 # Required variable, integer
          # addr_type: <value in [fqdn, ipv4, ipv6]>
          # fqdn: <string>
          # server_address: <string>
          # server_address6: <string>
          # server_type: ["update", "rating", "iot-query", "iot-collect", "vpatch-query",
          #               "iotv-query"]
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
        '/pm/config/device/{device}/global/system/central-management/server-list'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_centralmanagement_serverlist': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'addr-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['fqdn', 'ipv4', 'ipv6'], 'type': 'str'},
                'fqdn': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'server-address': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'server-address6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'server-type': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['update', 'rating', 'iot-query', 'iot-collect', 'vpatch-query', 'iotv-query'],
                    'elements': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_centralmanagement_serverlist'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
