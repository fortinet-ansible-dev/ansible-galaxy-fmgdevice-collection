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
module: fmgd_system_vinalarm
short_description: Configure vin alarm settings.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_vinalarm:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      psu_1_initial_voltage:
        aliases: ['psu-1-initial-voltage']
        type: int
        description: Initial voltage for the first PSU
      psu_1_threshold_low_percent:
        aliases: ['psu-1-threshold-low-percent']
        type: int
        description: Percentage threshold at which the first PSU voltage drops to trigger a low voltage alarm
      psu_2_initial_voltage:
        aliases: ['psu-2-initial-voltage']
        type: int
        description: Initial voltage for the second PSU
      psu_2_threshold_low_percent:
        aliases: ['psu-2-threshold-low-percent']
        type: int
        description: Percentage threshold at which the second PSU voltage drops to trigger a low voltage alarm
      status:
        type: str
        description: Enable/disable vin alarm.
        choices: ['disable', 'enable']
      psu_1_threshold_low:
        aliases: ['psu-1-threshold-low']
        type: int
        description: Threshold at which 1st PSU voltage drop to trigger low voltage alarm, in percent of voltage.
      psu_2_threshold_low:
        aliases: ['psu-2-threshold-low']
        type: int
        description: Threshold at which 2nd PSU voltage drop to trigger low voltage alarm, in percent of voltage.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure vin alarm settings.
      fortinet.fmgdevice.fmgd_system_vinalarm:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        system_vinalarm:
          # psu_1_initial_voltage: <integer>
          # psu_1_threshold_low_percent: <integer>
          # psu_2_initial_voltage: <integer>
          # psu_2_threshold_low_percent: <integer>
          # status: <value in [disable, enable]>
          # psu_1_threshold_low: <integer>
          # psu_2_threshold_low: <integer>
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
        '/pm/config/device/{device}/global/system/vin-alarm'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_vinalarm': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'psu-1-initial-voltage': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'psu-1-threshold-low-percent': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'psu-2-initial-voltage': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'psu-2-threshold-low-percent': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'psu-1-threshold-low': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'psu-2-threshold-low': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_vinalarm'),
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
