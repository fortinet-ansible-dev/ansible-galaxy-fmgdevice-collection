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
module: fmgd_system_ipam_rules
short_description: Configure IPAM allocation rules.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_ipam_rules:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      description:
        type: str
        description: Description.
      device:
        type: list
        elements: str
        description: Configure serial number or wildcard of FortiGate to match.
      dhcp:
        type: str
        description: Enable/disable DHCP server for matching IPAM interfaces.
        choices: ['disable', 'enable']
      interface:
        type: list
        elements: str
        description: Configure name or wildcard of interface to match.
      name:
        type: str
        description: IPAM rule name.
        required: true
      pool:
        type: list
        elements: str
        description: Configure name of IPAM pool to use.
      role:
        type: str
        description: Configure role of interface to match.
        choices: ['any', 'lan', 'wan', 'dmz', 'undefined']
      dhcp_template:
        aliases: ['dhcp-template']
        type: list
        elements: str
        description: DHCP template for assingned interface.
      item_name:
        aliases: ['item-name']
        type: list
        elements: str
        description: Configure name or wildcard of item to match.
      item_type:
        aliases: ['item-type']
        type: str
        description: Configure whether item is an interface or an address.
        choices: ['interface', 'address']
      vdom:
        type: list
        elements: str
        description: Configure which VDOMs have access to this IPAM rule.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure IPAM allocation rules.
      fortinet.fmgdevice.fmgd_system_ipam_rules:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        system_ipam_rules:
          name: "your value" # Required variable, string
          # description: <string>
          # device: <list or string>
          # dhcp: <value in [disable, enable]>
          # interface: <list or string>
          # pool: <list or string>
          # role: <value in [any, lan, wan, ...]>
          # dhcp_template: <list or string>
          # item_name: <list or string>
          # item_type: <value in [interface, address]>
          # vdom: <list or string>
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
        '/pm/config/device/{device}/global/system/ipam/rules'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_ipam_rules': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'device': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dhcp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'pool': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'role': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['any', 'lan', 'wan', 'dmz', 'undefined'], 'type': 'str'},
                'dhcp-template': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'item-name': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'item-type': {'v_range': [['8.0.0', '']], 'choices': ['interface', 'address'], 'type': 'str'},
                'vdom': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_ipam_rules'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
