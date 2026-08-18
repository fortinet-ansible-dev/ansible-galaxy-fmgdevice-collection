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
module: fmgd_log_threatweight_ips
short_description: IPS threat weight settings.
version_added: "1.1.0"
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
  log_threatweight_ips:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      critical_severity:
        aliases: ['critical-severity']
        type: str
        description: Threat weight score for IPS critical severity events.
        choices: ['disable', 'low', 'medium', 'high', 'critical']
      high_severity:
        aliases: ['high-severity']
        type: str
        description: Threat weight score for IPS high severity events.
        choices: ['disable', 'low', 'medium', 'high', 'critical']
      info_severity:
        aliases: ['info-severity']
        type: str
        description: Threat weight score for IPS info severity events.
        choices: ['disable', 'low', 'medium', 'high', 'critical']
      low_severity:
        aliases: ['low-severity']
        type: str
        description: Threat weight score for IPS low severity events.
        choices: ['disable', 'low', 'medium', 'high', 'critical']
      medium_severity:
        aliases: ['medium-severity']
        type: str
        description: Threat weight score for IPS medium severity events.
        choices: ['disable', 'low', 'medium', 'high', 'critical']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: IPS threat weight settings.
      fortinet.fmgdevice.fmgd_log_threatweight_ips:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        log_threatweight_ips:
          # critical_severity: <value in [disable, low, medium, ...]>
          # high_severity: <value in [disable, low, medium, ...]>
          # info_severity: <value in [disable, low, medium, ...]>
          # low_severity: <value in [disable, low, medium, ...]>
          # medium_severity: <value in [disable, low, medium, ...]>
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
        '/pm/config/device/{device}/vdom/{vdom}/log/threat-weight/ips'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'log_threatweight_ips': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'critical-severity': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                    'type': 'str'
                },
                'high-severity': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                    'type': 'str'
                },
                'info-severity': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                    'type': 'str'
                },
                'low-severity': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                    'type': 'str'
                },
                'medium-severity': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'log_threatweight_ips'),
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
