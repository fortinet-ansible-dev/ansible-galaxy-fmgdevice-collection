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
module: fmgd_casb_useractivity_match_tenantextraction
short_description: CASB user activity tenant extraction.
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
  user-activity:
    description: Deprecated, please use "user_activity"
    type: str
  user_activity:
    description: The parameter (user-activity) in requested url.
    type: str
  match:
    description: The parameter (match) in requested url.
    type: str
    required: true
  casb_useractivity_match_tenantextraction:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      filters:
        type: list
        elements: dict
        description: Filters.
        suboptions:
          body_type:
            aliases: ['body-type']
            type: str
            description: CASB tenant extraction filter body type.
            choices: ['json', 'form']
          direction:
            type: str
            description: CASB tenant extraction filter direction.
            choices: ['request', 'response']
          header_name:
            aliases: ['header-name']
            type: str
            description: CASB tenant extraction filter header name.
          id:
            type: int
            description: CASB tenant extraction filter ID.
          place:
            type: str
            description: CASB tenant extraction filter place type.
            choices: ['path', 'header', 'body']
      jq:
        type: str
        description: CASB user activity tenant extraction jq script.
      status:
        type: str
        description: Enable/disable CASB tenant extraction.
        choices: ['disable', 'enable']
      type:
        type: str
        description: CASB user activity tenant extraction type.
        choices: ['json-query']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: CASB user activity tenant extraction.
      fortinet.fmgdevice.fmgd_casb_useractivity_match_tenantextraction:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        user_activity: <your own value>
        match: <your own value>
        casb_useractivity_match_tenantextraction:
          # filters:
          #   - body_type: <value in [json, form]>
          #     direction: <value in [request, response]>
          #     header_name: <string>
          #     id: <integer>
          #     place: <value in [path, header, body]>
          # jq: <string>
          # status: <value in [disable, enable]>
          # type: <value in [json-query]>
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
        '/pm/config/device/{device}/vdom/{vdom}/casb/user-activity/{user-activity}/match/{match}/tenant-extraction'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'user-activity': {'type': 'str', 'api_name': 'user_activity'},
        'user_activity': {'type': 'str'},
        'match': {'required': True, 'type': 'str'},
        'casb_useractivity_match_tenantextraction': {
            'type': 'dict', 'v_range': [['7.6.4', '']],
            'options': {
                'filters': {
                    'v_range': [['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'body-type': {'v_range': [['7.6.4', '']], 'choices': ['json', 'form'], 'type': 'str'},
                        'direction': {'v_range': [['7.6.4', '']], 'choices': ['request', 'response'], 'type': 'str'},
                        'header-name': {'v_range': [['7.6.4', '']], 'type': 'str'},
                        'id': {'v_range': [['7.6.4', '']], 'type': 'int'},
                        'place': {'v_range': [['7.6.4', '']], 'choices': ['path', 'header', 'body'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'jq': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'status': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {'v_range': [['7.6.4', '']], 'choices': ['json-query'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'casb_useractivity_match_tenantextraction'),
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
