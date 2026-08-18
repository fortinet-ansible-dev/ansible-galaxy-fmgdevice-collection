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
module: fmgd_system_isfqueueprofile
short_description: Create a queue profile of switch.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_isfqueueprofile:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      bandwidth_unit:
        aliases: ['bandwidth-unit']
        type: str
        description: Unit of measurement for guaranteed and maximum bandwidth.
        choices: ['kbps', 'pps']
      burst_bps_granularity:
        aliases: ['burst-bps-granularity']
        type: str
        description: Burst granularity based on bytes per second.
        choices: ['disable', '512-bytes', '1k-bytes', '2k-bytes', '4k-bytes', '8k-bytes',
                  '16k-bytes', '32k-bytes']
      burst_pps_granularity:
        aliases: ['burst-pps-granularity']
        type: str
        description: Burst granularity based on packets per second.
        choices: ['disable', 'half-packet', '1-packet', '2-packets', '4-packets', '16-packets',
                  '65-packets', '262-packets']
      guaranteed_bandwidth:
        aliases: ['guaranteed-bandwidth']
        type: int
        description: Guaranteed bandwidth.
      maximum_bandwidth:
        aliases: ['maximum-bandwidth']
        type: int
        description: Upper bandwidth limit enforced.
      name:
        type: str
        description: Profile name.
        required: true
      burst_control:
        aliases: ['burst-control']
        type: str
        description: Burst control.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Create a queue profile of switch.
      fortinet.fmgdevice.fmgd_system_isfqueueprofile:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        system_isfqueueprofile:
          name: "your value" # Required variable, string
          # bandwidth_unit: <value in [kbps, pps]>
          # burst_bps_granularity: <value in [disable, 512-bytes, 1k-bytes, ...]>
          # burst_pps_granularity: <value in [disable, half-packet, 1-packet, ...]>
          # guaranteed_bandwidth: <integer>
          # maximum_bandwidth: <integer>
          # burst_control: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/system/isf-queue-profile'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_isfqueueprofile': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'bandwidth-unit': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['kbps', 'pps'], 'type': 'str'},
                'burst-bps-granularity': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['disable', '512-bytes', '1k-bytes', '2k-bytes', '4k-bytes', '8k-bytes', '16k-bytes', '32k-bytes'],
                    'type': 'str'
                },
                'burst-pps-granularity': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['disable', 'half-packet', '1-packet', '2-packets', '4-packets', '16-packets', '65-packets', '262-packets'],
                    'type': 'str'
                },
                'guaranteed-bandwidth': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'maximum-bandwidth': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'burst-control': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_isfqueueprofile'),
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
