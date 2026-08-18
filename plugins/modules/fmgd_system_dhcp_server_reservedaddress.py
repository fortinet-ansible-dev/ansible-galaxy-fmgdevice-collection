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
module: fmgd_system_dhcp_server_reservedaddress
short_description: Options for the DHCP server to assign IP settings to specific MAC addresses.
version_added: "1.1.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  vdom:
    description: The parameter (vdom) in requested url.
    type: str
    required: true
  server:
    description: The parameter (server) in requested url.
    type: str
    required: true
  system_dhcp_server_reservedaddress:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      action:
        type: str
        description: Options for the DHCP server to configure the client with the reserved MAC address.
        choices: ['assign', 'block', 'reserved']
      circuit_id:
        aliases: ['circuit-id']
        type: str
        description: Option 82 circuit-ID of the client that will get the reserved IP address.
      circuit_id_type:
        aliases: ['circuit-id-type']
        type: str
        description: DHCP option type.
        choices: ['hex', 'string']
      description:
        type: str
        description: Description.
      id:
        type: int
        description: ID.
        required: true
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
        choices: ['hex', 'string']
      type:
        type: str
        description: DHCP reserved-address type.
        choices: ['mac', 'option82']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Options for the DHCP server to assign IP settings to specific MAC addresses.
      fortinet.fmgdevice.fmgd_system_dhcp_server_reservedaddress:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        server: <your own value>
        state: present # <value in [present, absent]>
        system_dhcp_server_reservedaddress:
          id: 0 # Required variable, integer
          # action: <value in [assign, block, reserved]>
          # circuit_id: <string>
          # circuit_id_type: <value in [hex, string]>
          # description: <string>
          # ip: <string>
          # mac: <string>
          # remote_id: <string>
          # remote_id_type: <value in [hex, string]>
          # type: <value in [mac, option82]>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/dhcp/server/{server}/reserved-address'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'server': {'required': True, 'type': 'str'},
        'system_dhcp_server_reservedaddress': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['assign', 'block', 'reserved'], 'type': 'str'},
                'circuit-id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'circuit-id-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['hex', 'string'], 'type': 'str'},
                'description': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'mac': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'remote-id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'remote-id-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['hex', 'string'], 'type': 'str'},
                'type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['mac', 'option82'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_dhcp_server_reservedaddress'),
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
