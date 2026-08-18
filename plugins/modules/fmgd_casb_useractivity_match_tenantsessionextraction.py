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
module: fmgd_casb_useractivity_match_tenantsessionextraction
short_description: CASB user activity tenant session extraction.
version_added: "1.2.0"
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
  casb_useractivity_match_tenantsessionextraction:
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
            description: CASB content extraction filter body type.
            choices: ['json', 'form']
          cookie_name:
            aliases: ['cookie-name']
            type: str
            description: CASB content extraction filter cookie name.
          direction:
            type: str
            description: CASB content extraction filter direction.
            choices: ['request', 'response']
          header_name:
            aliases: ['header-name']
            type: str
            description: CASB content extraction filter header name.
          id:
            type: int
            description: CASB content extraction filter ID.
          place:
            type: str
            description: CASB content extraction filter place type.
            choices: ['header', 'path', 'body', 'cookie']
      jq:
        type: str
        description: CASB user activity session extraction jq script.
      session_match:
        aliases: ['session-match']
        type: str
        description: CASB user activity session match name.
      session_source:
        aliases: ['session-source']
        type: str
        description: Enable/disable CASB session extraction source flag.
        choices: ['disable', 'enable']
      status:
        type: str
        description: Enable/disable CASB session extraction.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: CASB user activity tenant session extraction.
      fortinet.fmgdevice.fmgd_casb_useractivity_match_tenantsessionextraction:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        user_activity: <your own value>
        match: <your own value>
        casb_useractivity_match_tenantsessionextraction:
          # filters:
          #   - body_type: <value in [json, form]>
          #     cookie_name: <string>
          #     direction: <value in [request, response]>
          #     header_name: <string>
          #     id: <integer>
          #     place: <value in [header, path, body, ...]>
          # jq: <string>
          # session_match: <string>
          # session_source: <value in [disable, enable]>
          # status: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/casb/user-activity/{user-activity}/match/{match}/tenant-session-extraction'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'user-activity': {'type': 'str', 'api_name': 'user_activity'},
        'user_activity': {'type': 'str'},
        'match': {'required': True, 'type': 'str'},
        'casb_useractivity_match_tenantsessionextraction': {
            'type': 'dict', 'v_range': [['8.0.0', '']],
            'options': {
                'filters': {
                    'v_range': [['8.0.0', '']],
                    'type': 'list',
                    'options': {
                        'body-type': {'v_range': [['8.0.0', '']], 'choices': ['json', 'form'], 'type': 'str'},
                        'cookie-name': {'v_range': [['8.0.0', '']], 'type': 'str'},
                        'direction': {'v_range': [['8.0.0', '']], 'choices': ['request', 'response'], 'type': 'str'},
                        'header-name': {'v_range': [['8.0.0', '']], 'type': 'str'},
                        'id': {'v_range': [['8.0.0', '']], 'type': 'int'},
                        'place': {'v_range': [['8.0.0', '']], 'choices': ['header', 'path', 'body', 'cookie'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'jq': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'session-match': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'session-source': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'casb_useractivity_match_tenantsessionextraction'),
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
