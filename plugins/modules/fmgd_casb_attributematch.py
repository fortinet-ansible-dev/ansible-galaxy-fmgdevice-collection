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
module: fmgd_casb_attributematch
short_description: Configure CASB SaaS application.
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
  casb_attributematch:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      application:
        type: list
        elements: str
        description: CASB tenant application name.
      attribute:
        type: list
        elements: dict
        description: Attribute.
        suboptions:
          case_sensitive:
            aliases: ['case-sensitive']
            type: str
            description: CASB attribute match case sensitive.
            choices: ['disable', 'enable']
          match_pattern:
            aliases: ['match-pattern']
            type: str
            description: CASB attribute match pattern.
            choices: ['simple', 'substr', 'regexp']
          match_value:
            aliases: ['match-value']
            type: str
            description: CASB attribute match value.
          name:
            type: str
            description: CASB attribute match name.
          negate:
            type: str
            description: Enable/disable what the matching strategy must not be.
            choices: ['disable', 'enable']
      match_strategy:
        aliases: ['match-strategy']
        type: str
        description: CASB tenant match strategy.
        choices: ['or', 'and', 'subset']
      name:
        type: str
        description: CASB tenant match name.
        required: true
      match:
        type: list
        elements: dict
        description: Match.
        suboptions:
          id:
            type: int
            description: CASB attribute match rule ID.
          rule:
            type: list
            elements: dict
            description: Rule.
            suboptions:
              attribute:
                type: str
                description: CASB attribute match name.
              case_sensitive:
                aliases: ['case-sensitive']
                type: str
                description: CASB attribute match case sensitive.
                choices: ['disable', 'enable']
              id:
                type: int
                description: CASB attribute rule ID.
              match_pattern:
                aliases: ['match-pattern']
                type: str
                description: CASB attribute match pattern.
                choices: ['simple', 'substr', 'regexp']
              match_value:
                aliases: ['match-value']
                type: str
                description: CASB attribute match value.
              negate:
                type: str
                description: Enable/disable what the matching strategy must not be.
                choices: ['disable', 'enable']
          rule_strategy:
            aliases: ['rule-strategy']
            type: str
            description: CASB attribute match rule strategy.
            choices: ['or', 'and']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure CASB SaaS application.
      fortinet.fmgdevice.fmgd_casb_attributematch:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        casb_attributematch:
          name: "your value" # Required variable, string
          # application: <list or string>
          # attribute:
          #   - case_sensitive: <value in [disable, enable]>
          #     match_pattern: <value in [simple, substr, regexp]>
          #     match_value: <string>
          #     name: <string>
          #     negate: <value in [disable, enable]>
          # match_strategy: <value in [or, and, subset]>
          # match:
          #   - id: <integer>
          #     rule:
          #       - attribute: <string>
          #         case_sensitive: <value in [disable, enable]>
          #         id: <integer>
          #         match_pattern: <value in [simple, substr, regexp]>
          #         match_value: <string>
          #         negate: <value in [disable, enable]>
          #     rule_strategy: <value in [or, and]>
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
        '/pm/config/device/{device}/vdom/{vdom}/casb/attribute-match'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'casb_attributematch': {
            'type': 'dict', 'v_range': [['7.6.2', '']],
            'options': {
                'application': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'attribute': {
                    'v_range': [['7.6.2', '']],
                    'type': 'list',
                    'options': {
                        'case-sensitive': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'match-pattern': {'v_range': [['7.6.2', '']], 'choices': ['simple', 'substr', 'regexp'], 'type': 'str'},
                        'match-value': {'v_range': [['7.6.2', '']], 'type': 'str'},
                        'name': {'v_range': [['7.6.2', '']], 'type': 'str'},
                        'negate': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'match-strategy': {'v_range': [['7.6.2', '']], 'choices': ['or', 'and', 'subset'], 'type': 'str'},
                'name': {'v_range': [['7.6.2', '']], 'required': True, 'type': 'str'},
                'match': {
                    'v_range': [['7.6.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'rule': {
                            'v_range': [['7.6.3', '']],
                            'type': 'list',
                            'options': {
                                'attribute': {'v_range': [['7.6.3', '']], 'type': 'str'},
                                'case-sensitive': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'id': {'v_range': [['7.6.3', '']], 'type': 'int'},
                                'match-pattern': {'v_range': [['7.6.3', '']], 'choices': ['simple', 'substr', 'regexp'], 'type': 'str'},
                                'match-value': {'v_range': [['7.6.3', '']], 'type': 'str'},
                                'negate': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'rule-strategy': {'v_range': [['7.6.3', '']], 'choices': ['or', 'and'], 'type': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'casb_attributematch'),
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
