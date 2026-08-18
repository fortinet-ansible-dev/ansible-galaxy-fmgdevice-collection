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
module: fmgd_switchcontroller_qos_queuepolicy
short_description: Configure FortiSwitch QoS egress queue policy.
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
  switchcontroller_qos_queuepolicy:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      cos_queue:
        aliases: ['cos-queue']
        type: list
        elements: dict
        description: Cos queue.
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
          weight:
            type: int
            description: Weight of weighted round robin scheduling.
      name:
        type: str
        description: QoS policy name.
        required: true
      rate_by:
        aliases: ['rate-by']
        type: str
        description: COS queue rate by kbps or percent.
        choices: ['kbps', 'percent']
      schedule:
        type: str
        description: COS queue scheduling.
        choices: ['strict', 'round-robin', 'weighted']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure FortiSwitch QoS egress queue policy.
      fortinet.fmgdevice.fmgd_switchcontroller_qos_queuepolicy:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_qos_queuepolicy:
          name: "your value" # Required variable, string
          # cos_queue:
          #   - description: <string>
          #     drop_policy: <value in [taildrop, weighted-random-early-detection]>
          #     ecn: <value in [disable, enable]>
          #     max_rate: <integer>
          #     max_rate_percent: <integer>
          #     min_rate: <integer>
          #     min_rate_percent: <integer>
          #     name: <string>
          #     weight: <integer>
          # rate_by: <value in [kbps, percent]>
          # schedule: <value in [strict, round-robin, weighted]>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/queue-policy'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'switchcontroller_qos_queuepolicy': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'cos-queue': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
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
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'weight': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'rate-by': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['kbps', 'percent'], 'type': 'str'},
                'schedule': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['strict', 'round-robin', 'weighted'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_qos_queuepolicy'),
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
