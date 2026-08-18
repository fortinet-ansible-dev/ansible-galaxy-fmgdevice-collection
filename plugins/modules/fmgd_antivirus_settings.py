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
module: fmgd_antivirus_settings
short_description: Configure AntiVirus settings.
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
  antivirus_settings:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      cache_infected_result:
        aliases: ['cache-infected-result']
        type: str
        description: Enable/disable cache of infected scan results
        choices: ['disable', 'enable']
      grayware:
        type: str
        description: Enable/disable grayware detection when an AntiVirus profile is applied to traffic.
        choices: ['disable', 'enable']
      machine_learning_detection:
        aliases: ['machine-learning-detection']
        type: str
        description: Use machine learning based malware detection.
        choices: ['disable', 'enable', 'monitor']
      override_timeout:
        aliases: ['override-timeout']
        type: int
        description: Override the large file scan timeout value in seconds
      use_extreme_db:
        aliases: ['use-extreme-db']
        type: str
        description: Enable/disable the use of Extreme AVDB.
        choices: ['disable', 'enable']
      cache_clean_result:
        aliases: ['cache-clean-result']
        type: str
        description: Cache clean result.
        choices: ['disable', 'enable']
      default_db:
        aliases: ['default-db']
        type: str
        description: Select the AV database to be used for AV scanning.
        choices: ['normal', 'extended', 'flow-based', 'extreme']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure AntiVirus settings.
      fortinet.fmgdevice.fmgd_antivirus_settings:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        antivirus_settings:
          # cache_infected_result: <value in [disable, enable]>
          # grayware: <value in [disable, enable]>
          # machine_learning_detection: <value in [disable, enable, monitor]>
          # override_timeout: <integer>
          # use_extreme_db: <value in [disable, enable]>
          # cache_clean_result: <value in [disable, enable]>
          # default_db: <value in [normal, extended, flow-based, ...]>
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
        '/pm/config/device/{device}/vdom/{vdom}/antivirus/settings'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'antivirus_settings': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'cache-infected-result': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'grayware': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'machine-learning-detection': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['disable', 'enable', 'monitor'],
                    'type': 'str'
                },
                'override-timeout': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'use-extreme-db': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cache-clean-result': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'default-db': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']],
                    'choices': ['normal', 'extended', 'flow-based', 'extreme'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'antivirus_settings'),
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
