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
module: fmgd_firewall_pfcp
short_description: Configure PFCP.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  vdom:
    description: The parameter (vdom) in requested url.
    type: str
    required: true
  firewall_pfcp:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      denied_log:
        aliases: ['denied-log']
        type: str
        description: Enable/disable logging denied PFCP packets.
        choices: ['disable', 'enable']
      forwarded_log:
        aliases: ['forwarded-log']
        type: str
        description: Enable/disable logging forwarded PFCP packets.
        choices: ['disable', 'enable']
      invalid_reserved_field:
        aliases: ['invalid-reserved-field']
        type: str
        description: Allow or deny invalid reserved field in PFCP header packets.
        choices: ['deny', 'allow']
      log_freq:
        aliases: ['log-freq']
        type: int
        description: Logging frequency of PFCP packets.
      max_message_length:
        aliases: ['max-message-length']
        type: int
        description: Maximum message length.
      message_filter:
        aliases: ['message-filter']
        type: list
        elements: str
        description: PFCP message filter.
      min_message_length:
        aliases: ['min-message-length']
        type: int
        description: Minimum message length.
      monitor_mode:
        aliases: ['monitor-mode']
        type: str
        description: PFCP monitor mode.
        choices: ['disable', 'enable', 'vdom']
      name:
        type: str
        description: PFCP profile name.
        required: true
      pfcp_timeout:
        aliases: ['pfcp-timeout']
        type: int
        description: Set PFCP timeout
      traffic_count_log:
        aliases: ['traffic-count-log']
        type: str
        description: Enable/disable logging session traffic counter.
        choices: ['disable', 'enable']
      unknown_version:
        aliases: ['unknown-version']
        type: str
        description: Allow or deny unknown version packets.
        choices: ['deny', 'allow']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure PFCP.
      fortinet.fmgdevice.fmgd_firewall_pfcp:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_pfcp:
          name: "your value" # Required variable, string
          # denied_log: <value in [disable, enable]>
          # forwarded_log: <value in [disable, enable]>
          # invalid_reserved_field: <value in [deny, allow]>
          # log_freq: <integer>
          # max_message_length: <integer>
          # message_filter: <list or string>
          # min_message_length: <integer>
          # monitor_mode: <value in [disable, enable, vdom]>
          # pfcp_timeout: <integer>
          # traffic_count_log: <value in [disable, enable]>
          # unknown_version: <value in [deny, allow]>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/pfcp'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_pfcp': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'denied-log': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'forwarded-log': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'invalid-reserved-field': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                'log-freq': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'max-message-length': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'message-filter': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'min-message-length': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'monitor-mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'vdom'], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'pfcp-timeout': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'traffic-count-log': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'unknown-version': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_pfcp'),
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
