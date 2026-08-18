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
module: fmgd_notification
short_description: Event notification configuration.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  notification:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      maximum_rate:
        aliases: ['maximum-rate']
        type: int
        description: The maximum rate for notification messages
      maximum_retries:
        aliases: ['maximum-retries']
        type: int
        description: The maximum number of retries allowed for each notification message
      maximum_sessions:
        aliases: ['maximum-sessions']
        type: int
        description: The maximum number of simultaneous sessions with the MMSC
      mem_percent:
        aliases: ['mem-percent']
        type: int
        description: Percentage of memory the notification cache is allowed to use
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Event notification configuration.
      fortinet.fmgdevice.fmgd_notification:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        notification:
          # maximum_rate: <integer>
          # maximum_retries: <integer>
          # maximum_sessions: <integer>
          # mem_percent: <integer>
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
        '/pm/config/device/{device}/global/notification'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'notification': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']],
            'options': {
                'maximum-rate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'int'},
                'maximum-retries': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'int'},
                'maximum-sessions': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'int'},
                'mem-percent': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'notification'),
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
