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
module: fmgd_system_storage
short_description: Configure logical storage.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_storage:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      device:
        type: str
        description: Partition device.
      media_status:
        aliases: ['media-status']
        type: str
        description: The physical status of current media.
        choices: ['disable', 'enable', 'fail']
      name:
        type: str
        description: Storage name.
        required: true
      order:
        type: int
        description: Set storage order.
      partition:
        type: str
        description: Label of underlying partition.
      size:
        type: int
        description: Partition size.
      status:
        type: str
        description: Enable/disable storage.
        choices: ['disable', 'enable']
      usage:
        type: str
        description: Use hard disk for logging and WAN Optimization.
        choices: ['log', 'wanopt', 'mix', 'unused']
      wanopt_mode:
        aliases: ['wanopt-mode']
        type: str
        description: WAN Optimization mode
        choices: ['mix', 'wanopt', 'webcache']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure logical storage.
      fortinet.fmgdevice.fmgd_system_storage:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        system_storage:
          name: "your value" # Required variable, string
          # device: <string>
          # media_status: <value in [disable, enable, fail]>
          # order: <integer>
          # partition: <string>
          # size: <integer>
          # status: <value in [disable, enable]>
          # usage: <value in [log, wanopt, mix, ...]>
          # wanopt_mode: <value in [mix, wanopt, webcache]>
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
        '/pm/config/device/{device}/global/system/storage'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_storage': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'device': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'media-status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'fail'], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'order': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'partition': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'size': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'usage': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['log', 'wanopt', 'mix', 'unused'], 'type': 'str'},
                'wanopt-mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['mix', 'wanopt', 'webcache'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_storage'),
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
