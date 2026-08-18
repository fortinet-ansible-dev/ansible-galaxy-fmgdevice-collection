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
module: fmgd_switchcontroller_qos_queuepolicy_cosqueue
short_description: COS queue configuration.
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
  queue-policy:
    description: Deprecated, please use "queue_policy"
    type: str
  queue_policy:
    description: The parameter (queue-policy) in requested url.
    type: str
  switchcontroller_qos_queuepolicy_cosqueue:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      description:
        type: str
        description: Description of the COS queue.
      drop_policy:
        aliases: ['drop-policy']
        type: str
        description: COS queue drop policy.
        choices: ['taildrop', 'weighted-random-early-detection']
      ecn:
        type: str
        description: Enable/disable ECN packet marking to drop eligible packets.
        choices: ['disable', 'enable']
      max_rate:
        aliases: ['max-rate']
        type: int
        description: Maximum rate
      max_rate_percent:
        aliases: ['max-rate-percent']
        type: int
        description: Maximum rate
      min_rate:
        aliases: ['min-rate']
        type: int
        description: Minimum rate
      min_rate_percent:
        aliases: ['min-rate-percent']
        type: int
        description: Minimum rate
      name:
        type: str
        description: Cos queue ID.
        required: true
      weight:
        type: int
        description: Weight of weighted round robin scheduling.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: COS queue configuration.
      fortinet.fmgdevice.fmgd_switchcontroller_qos_queuepolicy_cosqueue:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        queue_policy: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_qos_queuepolicy_cosqueue:
          name: "your value" # Required variable, string
          # description: <string>
          # drop_policy: <value in [taildrop, weighted-random-early-detection]>
          # ecn: <value in [disable, enable]>
          # max_rate: <integer>
          # max_rate_percent: <integer>
          # min_rate: <integer>
          # min_rate_percent: <integer>
          # weight: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/queue-policy/{queue-policy}/cos-queue'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'queue-policy': {'type': 'str', 'api_name': 'queue_policy'},
        'queue_policy': {'type': 'str'},
        'switchcontroller_qos_queuepolicy_cosqueue': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'drop-policy': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['taildrop', 'weighted-random-early-detection'],
                    'type': 'str'
                },
                'ecn': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'max-rate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'max-rate-percent': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'min-rate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'min-rate-percent': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'weight': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_qos_queuepolicy_cosqueue'),
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
