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
module: fmgd_extensioncontroller_extender_wanextension
short_description: FortiExtender wan extension configuration.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  vdom:
    description: The parameter (vdom) in requested url.
    type: str
    required: true
  extender:
    description: The parameter (extender) in requested url.
    type: str
    required: true
  extensioncontroller_extender_wanextension:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      modem1_extension:
        aliases: ['modem1-extension']
        type: list
        elements: str
        description: FortiExtender interface name.
      modem2_extension:
        aliases: ['modem2-extension']
        type: list
        elements: str
        description: FortiExtender interface name.
      modem1_pdn1_interface:
        aliases: ['modem1-pdn1-interface']
        type: list
        elements: str
        description: FortiExtender interface name.
      modem1_pdn2_interface:
        aliases: ['modem1-pdn2-interface']
        type: list
        elements: str
        description: FortiExtender interface name.
      modem1_pdn3_interface:
        aliases: ['modem1-pdn3-interface']
        type: list
        elements: str
        description: FortiExtender interface name.
      modem1_pdn4_interface:
        aliases: ['modem1-pdn4-interface']
        type: list
        elements: str
        description: FortiExtender interface name.
      modem2_pdn1_interface:
        aliases: ['modem2-pdn1-interface']
        type: list
        elements: str
        description: FortiExtender interface name.
      modem2_pdn2_interface:
        aliases: ['modem2-pdn2-interface']
        type: list
        elements: str
        description: FortiExtender interface name.
      modem2_pdn3_interface:
        aliases: ['modem2-pdn3-interface']
        type: list
        elements: str
        description: FortiExtender interface name.
      modem2_pdn4_interface:
        aliases: ['modem2-pdn4-interface']
        type: list
        elements: str
        description: FortiExtender interface name.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: FortiExtender wan extension configuration.
      fortinet.fmgdevice.fmgd_extensioncontroller_extender_wanextension:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        extender: <your own value>
        extensioncontroller_extender_wanextension:
          # modem1_extension: <list or string>
          # modem2_extension: <list or string>
          # modem1_pdn1_interface: <list or string>
          # modem1_pdn2_interface: <list or string>
          # modem1_pdn3_interface: <list or string>
          # modem1_pdn4_interface: <list or string>
          # modem2_pdn1_interface: <list or string>
          # modem2_pdn2_interface: <list or string>
          # modem2_pdn3_interface: <list or string>
          # modem2_pdn4_interface: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/extension-controller/extender/{extender}/wan-extension'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'extender': {'required': True, 'type': 'str'},
        'extensioncontroller_extender_wanextension': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'modem1-extension': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'modem2-extension': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'modem1-pdn1-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'modem1-pdn2-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'modem1-pdn3-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'modem1-pdn4-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'modem2-pdn1-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'modem2-pdn2-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'modem2-pdn3-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'modem2-pdn4-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extensioncontroller_extender_wanextension'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
