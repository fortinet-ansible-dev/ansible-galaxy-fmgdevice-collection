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
module: fmgd_system_ipam_pools_exclude
short_description: Configure pool exclude subnets.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  pools:
    description: The parameter (pools) in requested url.
    type: str
    required: true
  system_ipam_pools_exclude:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      ID:
        type: int
        description: Exclude ID.
      exclude_subnet:
        aliases: ['exclude-subnet']
        type: list
        elements: str
        description: Configure subnet to exclude from the IPAM pool.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure pool exclude subnets.
      fortinet.fmgdevice.fmgd_system_ipam_pools_exclude:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        pools: <your own value>
        state: present # <value in [present, absent]>
        system_ipam_pools_exclude:
          # ID: <integer>
          # exclude_subnet: <list or string>
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
        '/pm/config/device/{device}/global/system/ipam/pools/{pools}/exclude'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'pools': {'required': True, 'type': 'str'},
        'system_ipam_pools_exclude': {
            'type': 'dict', 'v_range': [['7.4.3', '']],
            'options': {
                'ID': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'exclude-subnet': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_ipam_pools_exclude'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
