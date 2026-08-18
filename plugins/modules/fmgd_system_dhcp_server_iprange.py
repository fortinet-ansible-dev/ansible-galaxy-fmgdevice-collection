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
module: fmgd_system_dhcp_server_iprange
short_description: DHCP IP range configuration.
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
  system_dhcp_server_iprange:
    description: The top level parameters set.
    required: false
    type: dict
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
        required: true
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
        choices: ['disable', 'enable']
      uci_string:
        aliases: ['uci-string']
        type: list
        elements: str
        description: One or more UCI strings in quotes separated by spaces.
      vci_match:
        aliases: ['vci-match']
        type: str
        description: Enable/disable vendor class identifier
        choices: ['disable', 'enable']
      vci_string:
        aliases: ['vci-string']
        type: list
        elements: str
        description: One or more VCI strings in quotes separated by spaces.
      oui_match:
        aliases: ['oui-match']
        type: str
        description: Enable/disable organizationally unique identifier
        choices: ['disable', 'enable']
      oui_string:
        aliases: ['oui-string']
        type: list
        elements: str
        description: One or more OUI strings in quotes separated by spaces
      vendor:
        type: str
        description: Vendor this ip-range will be assigned to.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: DHCP IP range configuration.
      fortinet.fmgdevice.fmgd_system_dhcp_server_iprange:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        server: <your own value>
        state: present # <value in [present, absent]>
        system_dhcp_server_iprange:
          id: 0 # Required variable, integer
          # end_ip: <string>
          # lease_time: <integer>
          # start_ip: <string>
          # uci_match: <value in [disable, enable]>
          # uci_string: <list or string>
          # vci_match: <value in [disable, enable]>
          # vci_string: <list or string>
          # oui_match: <value in [disable, enable]>
          # oui_string: <list or string>
          # vendor: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/dhcp/server/{server}/ip-range'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'server': {'required': True, 'type': 'str'},
        'system_dhcp_server_iprange': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'end-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'lease-time': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'start-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'uci-match': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uci-string': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'vci-match': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vci-string': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'oui-match': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'oui-string': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'vendor': {'v_range': [['8.0.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_dhcp_server_iprange'),
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
