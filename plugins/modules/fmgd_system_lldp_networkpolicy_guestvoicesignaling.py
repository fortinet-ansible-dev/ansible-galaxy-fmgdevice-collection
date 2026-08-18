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
module: fmgd_system_lldp_networkpolicy_guestvoicesignaling
short_description: Guest Voice Signaling.
version_added: "1.0.0"
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
  network-policy:
    description: Deprecated, please use "network_policy"
    type: str
  network_policy:
    description: The parameter (network-policy) in requested url.
    type: str
  system_lldp_networkpolicy_guestvoicesignaling:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      dscp:
        type: int
        description: Differentiated Services Code Point
      priority:
        type: int
        description: '802.'
      status:
        type: str
        description: Enable/disable advertising this policy.
        choices: ['disable', 'enable']
      tag:
        type: str
        description: Advertise tagged or untagged traffic.
        choices: ['none', 'dot1q', 'dot1p']
      vlan:
        type: int
        description: '802.'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Guest Voice Signaling.
      fortinet.fmgdevice.fmgd_system_lldp_networkpolicy_guestvoicesignaling:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        network_policy: <your own value>
        system_lldp_networkpolicy_guestvoicesignaling:
          # dscp: <integer>
          # priority: <integer>
          # status: <value in [disable, enable]>
          # tag: <value in [none, dot1q, dot1p]>
          # vlan: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/lldp/network-policy/{network-policy}/guest-voice-signaling'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'network-policy': {'type': 'str', 'api_name': 'network_policy'},
        'network_policy': {'type': 'str'},
        'system_lldp_networkpolicy_guestvoicesignaling': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'dscp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tag': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'dot1q', 'dot1p'], 'type': 'str'},
                'vlan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_lldp_networkpolicy_guestvoicesignaling'),
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
