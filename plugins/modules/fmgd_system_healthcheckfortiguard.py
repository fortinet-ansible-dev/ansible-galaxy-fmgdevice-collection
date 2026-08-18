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
module: fmgd_system_healthcheckfortiguard
short_description: SD-WAN status checking or health checking.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_healthcheckfortiguard:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      name:
        type: str
        description: Status check or predefined health-check targets name.
        required: true
      obsolete:
        type: int
        description: Obsolete.
      protocol:
        type: str
        description: Protocol name.
        choices: ['ping', 'tcp-echo', 'udp-echo', 'http', 'twamp', 'dns', 'tcp-connect', 'ftp',
                  'https']
      server:
        type: str
        description: Status check or predefined health-check domain name.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: SD-WAN status checking or health checking.
      fortinet.fmgdevice.fmgd_system_healthcheckfortiguard:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        system_healthcheckfortiguard:
          name: "your value" # Required variable, string
          # obsolete: <integer>
          # protocol: <value in [ping, tcp-echo, udp-echo, ...]>
          # server: <string>
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
        '/pm/config/device/{device}/global/system/health-check-fortiguard'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_healthcheckfortiguard': {
            'type': 'dict', 'v_range': [['7.6.2', '']],
            'options': {
                'name': {'v_range': [['7.6.2', '']], 'required': True, 'type': 'str'},
                'obsolete': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'protocol': {
                    'v_range': [['7.6.2', '']],
                    'choices': ['ping', 'tcp-echo', 'udp-echo', 'http', 'twamp', 'dns', 'tcp-connect', 'ftp', 'https'],
                    'type': 'str'
                },
                'server': {'v_range': [['7.6.2', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_healthcheckfortiguard'),
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
