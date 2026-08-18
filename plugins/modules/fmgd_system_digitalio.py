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
module: fmgd_system_digitalio
short_description: Configure digital-io.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_digitalio:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      input1_detection_mode:
        aliases: ['input1-detection-mode']
        type: str
        description: Set input1 to default
        choices: ['default', 'voltage']
      input2_detection_mode:
        aliases: ['input2-detection-mode']
        type: str
        description: Set input2 to default
        choices: ['default', 'voltage']
      output_keep_last_state:
        aliases: ['output-keep-last-state']
        type: str
        description: Enable
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure digital-io.
      fortinet.fmgdevice.fmgd_system_digitalio:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        system_digitalio:
          # input1_detection_mode: <value in [default, voltage]>
          # input2_detection_mode: <value in [default, voltage]>
          # output_keep_last_state: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/system/digital-io'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_digitalio': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'input1-detection-mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['default', 'voltage'], 'type': 'str'},
                'input2-detection-mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['default', 'voltage'], 'type': 'str'},
                'output-keep-last-state': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_digitalio'),
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
