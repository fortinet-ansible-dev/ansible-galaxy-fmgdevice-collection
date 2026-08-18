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
module: fmgd_casb_attributematch_attribute
short_description: CASB tenant match rules.
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
  attribute-match:
    description: Deprecated, please use "attribute_match"
    type: str
  attribute_match:
    description: The parameter (attribute-match) in requested url.
    type: str
  casb_attributematch_attribute:
    description: The top level parameters set.
    required: false
    type: dict
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
        required: true
      negate:
        type: str
        description: Enable/disable what the matching strategy must not be.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: CASB tenant match rules.
      fortinet.fmgdevice.fmgd_casb_attributematch_attribute:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        attribute_match: <your own value>
        state: present # <value in [present, absent]>
        casb_attributematch_attribute:
          name: "your value" # Required variable, string
          # case_sensitive: <value in [disable, enable]>
          # match_pattern: <value in [simple, substr, regexp]>
          # match_value: <string>
          # negate: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/casb/attribute-match/{attribute-match}/attribute'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'attribute-match': {'type': 'str', 'api_name': 'attribute_match'},
        'attribute_match': {'type': 'str'},
        'casb_attributematch_attribute': {
            'type': 'dict', 'v_range': [['7.6.2', '']],
            'options': {
                'case-sensitive': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'match-pattern': {'v_range': [['7.6.2', '']], 'choices': ['simple', 'substr', 'regexp'], 'type': 'str'},
                'match-value': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'name': {'v_range': [['7.6.2', '']], 'required': True, 'type': 'str'},
                'negate': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'casb_attributematch_attribute'),
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
