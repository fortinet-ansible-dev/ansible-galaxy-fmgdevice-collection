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
module: fmgd_system_virtualwanlink_healthcheck_sla
short_description: Service level agreement
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
  health-check:
    description: Deprecated, please use "health_check"
    type: str
  health_check:
    description: The parameter (health-check) in requested url.
    type: str
  system_virtualwanlink_healthcheck_sla:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      id:
        type: int
        description: SLA ID.
        required: true
      jitter_threshold:
        aliases: ['jitter-threshold']
        type: int
        description:
          - Support meta variable
          - Jitter for SLA to make decision in milliseconds.
      latency_threshold:
        aliases: ['latency-threshold']
        type: int
        description:
          - Support meta variable
          - Latency for SLA to make decision in milliseconds.
      link_cost_factor:
        aliases: ['link-cost-factor']
        type: list
        elements: str
        description: Criteria on which to base link selection.
        choices: ['latency', 'jitter', 'packet-loss']
      packetloss_threshold:
        aliases: ['packetloss-threshold']
        type: int
        description:
          - Support meta variable
          - Packet loss for SLA to make decision in percentage.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Service level agreement
      fortinet.fmgdevice.fmgd_system_virtualwanlink_healthcheck_sla:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        health_check: <your own value>
        state: present # <value in [present, absent]>
        system_virtualwanlink_healthcheck_sla:
          id: 0 # Required variable, integer
          # jitter_threshold: <integer>
          # latency_threshold: <integer>
          # link_cost_factor: ["latency", "jitter", "packet-loss"]
          # packetloss_threshold: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/health-check/{health-check}/sla'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'health-check': {'type': 'str', 'api_name': 'health_check'},
        'health_check': {'type': 'str'},
        'system_virtualwanlink_healthcheck_sla': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']],
            'options': {
                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'required': True, 'type': 'int'},
                'jitter-threshold': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'int'},
                'latency-threshold': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'int'},
                'link-cost-factor': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']],
                    'type': 'list',
                    'choices': ['latency', 'jitter', 'packet-loss'],
                    'elements': 'str'
                },
                'packetloss-threshold': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_virtualwanlink_healthcheck_sla'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
