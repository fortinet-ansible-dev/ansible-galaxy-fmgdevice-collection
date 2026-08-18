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
module: fmgd_system_console
short_description: Configure console.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_console:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      baudrate:
        type: str
        description: Console baud rate.
        choices: ['9600', '19200', '38400', '57600', '115200']
      fortiexplorer:
        type: str
        description: Enable/disable access for FortiExplorer.
        choices: ['disable', 'enable']
      login:
        type: str
        description: Enable/disable serial console and FortiExplorer.
        choices: ['disable', 'enable']
      output:
        type: str
        description: Console output mode.
        choices: ['standard', 'more']
      mode:
        type: str
        description: Console mode.
        choices: ['line', 'batch']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure console.
      fortinet.fmgdevice.fmgd_system_console:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        system_console:
          # baudrate: <value in [9600, 19200, 38400, ...]>
          # fortiexplorer: <value in [disable, enable]>
          # login: <value in [disable, enable]>
          # output: <value in [standard, more]>
          # mode: <value in [line, batch]>
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
        '/pm/config/device/{device}/global/system/console'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_console': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'baudrate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['9600', '19200', '38400', '57600', '115200'], 'type': 'str'},
                'fortiexplorer': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'login': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'output': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['standard', 'more'], 'type': 'str'},
                'mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['line', 'batch'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_console'),
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
