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
module: fmgd_system_dhcp_template_options
short_description: DHCP options.
version_added: "1.2.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  template:
    description: The parameter (template) in requested url.
    type: str
    required: true
  system_dhcp_template_options:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      code:
        type: int
        description: DHCP option code.
      id:
        type: int
        description: ID.
        required: true
      ip:
        type: str
        description: DHCP option IPs.
      type:
        type: str
        description: DHCP option type.
        choices: ['hex', 'string', 'ip', 'fqdn']
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
      value:
        type: str
        description: DHCP option value.
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
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: DHCP options.
      fortinet.fmgdevice.fmgd_system_dhcp_template_options:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        template: <your own value>
        state: present # <value in [present, absent]>
        system_dhcp_template_options:
          id: 0 # Required variable, integer
          # code: <integer>
          # ip: <string>
          # type: <value in [hex, string, ip, ...]>
          # uci_match: <value in [disable, enable]>
          # uci_string: <list or string>
          # value: <string>
          # vci_match: <value in [disable, enable]>
          # vci_string: <list or string>
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
        '/pm/config/device/{device}/global/system/dhcp/template/{template}/options'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'template': {'required': True, 'type': 'str'},
        'system_dhcp_template_options': {
            'type': 'dict', 'v_range': [['8.0.0', '']],
            'options': {
                'code': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'id': {'v_range': [['8.0.0', '']], 'required': True, 'type': 'int'},
                'ip': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'type': {'v_range': [['8.0.0', '']], 'choices': ['hex', 'string', 'ip', 'fqdn'], 'type': 'str'},
                'uci-match': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uci-string': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'value': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'vci-match': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vci-string': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_dhcp_template_options'),
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
