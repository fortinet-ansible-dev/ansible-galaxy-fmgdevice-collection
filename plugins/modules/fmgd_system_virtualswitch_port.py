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
module: fmgd_system_virtualswitch_port
short_description: Configure member ports.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  virtual-switch:
    description: Deprecated, please use "virtual_switch"
    type: str
  virtual_switch:
    description: The parameter (virtual-switch) in requested url.
    type: str
  system_virtualswitch_port:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      alias:
        type: str
        description: Alias.
      name:
        required: true
        type: list
        elements: str
        description: Physical interface name.
      poe:
        type: str
        description: Enable/disable PoE status.
        choices: ['disable', 'enable']
      status:
        type: str
        description: Interface status.
        choices: ['down', 'up']
      speed:
        type: str
        description: Interface speed.
        choices: ['auto', '10full', '10half', '100full', '100half', '1000full', '1000half',
                  '10000full', '1000auto', '10000auto', '40000full', '100Gfull', '25000full']
      mediatype:
        type: str
        description: Select SFP media interface type.
        choices: ['cfp2-sr10', 'cfp2-lr4']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure member ports.
      fortinet.fmgdevice.fmgd_system_virtualswitch_port:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        virtual_switch: <your own value>
        state: present # <value in [present, absent]>
        system_virtualswitch_port:
          name: [] # Required variable
          # alias: <string>
          # poe: <value in [disable, enable]>
          # status: <value in [down, up]>
          # speed: <value in [auto, 10full, 10half, ...]>
          # mediatype: <value in [cfp2-sr10, cfp2-lr4]>
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
        '/pm/config/device/{device}/global/system/virtual-switch/{virtual-switch}/port'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'virtual-switch': {'type': 'str', 'api_name': 'virtual_switch'},
        'virtual_switch': {'type': 'str'},
        'system_virtualswitch_port': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'alias': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'list', 'elements': 'str'},
                'poe': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['down', 'up'], 'type': 'str'},
                'speed': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': [
                        'auto', '10full', '10half', '100full', '100half', '1000full', '1000half', '10000full', '1000auto', '10000auto', '40000full',
                        '100Gfull', '25000full'
                    ],
                    'type': 'str'
                },
                'mediatype': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['cfp2-sr10', 'cfp2-lr4'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_virtualswitch_port'),
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
