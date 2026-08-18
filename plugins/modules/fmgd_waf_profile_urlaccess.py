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
module: fmgd_waf_profile_urlaccess
short_description: URL access list.
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
  profile:
    description: The parameter (profile) in requested url.
    type: str
    required: true
  waf_profile_urlaccess:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      access_pattern:
        aliases: ['access-pattern']
        type: list
        elements: dict
        description: Access pattern.
        suboptions:
          id:
            type: int
            description: URL access pattern ID.
          negate:
            type: str
            description: Enable/disable match negation.
            choices: ['disable', 'enable']
          pattern:
            type: str
            description: URL pattern.
          regex:
            type: str
            description: Enable/disable regular expression based pattern match.
            choices: ['disable', 'enable']
          srcaddr:
            type: list
            elements: str
            description: Source address.
      action:
        type: str
        description: Action.
        choices: ['bypass', 'permit', 'block']
      address:
        type: list
        elements: str
        description: Host address.
      id:
        type: int
        description: URL access ID.
        required: true
      log:
        type: str
        description: Enable/disable logging.
        choices: ['disable', 'enable']
      severity:
        type: str
        description: Severity.
        choices: ['low', 'medium', 'high']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: URL access list.
      fortinet.fmgdevice.fmgd_waf_profile_urlaccess:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        profile: <your own value>
        state: present # <value in [present, absent]>
        waf_profile_urlaccess:
          id: 0 # Required variable, integer
          # access_pattern:
          #   - id: <integer>
          #     negate: <value in [disable, enable]>
          #     pattern: <string>
          #     regex: <value in [disable, enable]>
          #     srcaddr: <list or string>
          # action: <value in [bypass, permit, block]>
          # address: <list or string>
          # log: <value in [disable, enable]>
          # severity: <value in [low, medium, high]>
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
        '/pm/config/device/{device}/vdom/{vdom}/waf/profile/{profile}/url-access'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'waf_profile_urlaccess': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'access-pattern': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'negate': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pattern': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'regex': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'srcaddr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['bypass', 'permit', 'block'], 'type': 'str'},
                'address': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'severity': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'waf_profile_urlaccess'),
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
