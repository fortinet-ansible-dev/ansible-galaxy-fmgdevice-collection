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
module: fmgd_router_prefixlist6_rule
short_description: IPv6 prefix list rule.
version_added: "1.1.0"
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
  prefix-list6:
    description: Deprecated, please use "prefix_list6"
    type: str
  prefix_list6:
    description: The parameter (prefix-list6) in requested url.
    type: str
  router_prefixlist6_rule:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      action:
        type: str
        description: Permit or deny packets that match this rule.
        choices: ['permit', 'deny']
      flags:
        type: int
        description: Flags.
      ge:
        type: int
        description: Minimum prefix length to be matched
      id:
        type: int
        description: Rule ID.
        required: true
      le:
        type: int
        description: Maximum prefix length to be matched
      prefix6:
        type: str
        description:
          - Support meta variable
          - IPv6 prefix to define regular filter criteria, such as any or subnets.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: IPv6 prefix list rule.
      fortinet.fmgdevice.fmgd_router_prefixlist6_rule:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        prefix_list6: <your own value>
        state: present # <value in [present, absent]>
        router_prefixlist6_rule:
          id: 0 # Required variable, integer
          # action: <value in [permit, deny]>
          # flags: <integer>
          # ge: <integer>
          # le: <integer>
          # prefix6: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/prefix-list6/{prefix-list6}/rule'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'prefix-list6': {'type': 'str', 'api_name': 'prefix_list6'},
        'prefix_list6': {'type': 'str'},
        'router_prefixlist6_rule': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['permit', 'deny'], 'type': 'str'},
                'flags': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'ge': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'le': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'prefix6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_prefixlist6_rule'),
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
