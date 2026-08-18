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
module: fmgd_report_chart_column_mapping
short_description: Show detail in certain display value for certain condition.
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
  chart:
    description: The parameter (chart) in requested url.
    type: str
    required: true
  column:
    description: The parameter (column) in requested url.
    type: str
    required: true
  report_chart_column_mapping:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      displayname:
        type: str
        description: Display name.
      id:
        type: int
        description: Id.
        required: true
      op:
        type: str
        description: Comparision operater.
        choices: ['none', 'greater', 'greater-equal', 'less', 'less-equal', 'equal', 'between']
      value_type:
        aliases: ['value-type']
        type: str
        description: Value type.
        choices: ['string', 'integer']
      value1:
        type: str
        description: Value 1.
      value2:
        type: str
        description: Value 2.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Show detail in certain display value for certain condition.
      fortinet.fmgdevice.fmgd_report_chart_column_mapping:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        chart: <your own value>
        column: <your own value>
        state: present # <value in [present, absent]>
        report_chart_column_mapping:
          id: 0 # Required variable, integer
          # displayname: <string>
          # op: <value in [none, greater, greater-equal, ...]>
          # value_type: <value in [string, integer]>
          # value1: <string>
          # value2: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/column/{column}/mapping'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'chart': {'required': True, 'type': 'str'},
        'column': {'required': True, 'type': 'str'},
        'report_chart_column_mapping': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']],
            'options': {
                'displayname': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'required': True, 'type': 'int'},
                'op': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']],
                    'choices': ['none', 'greater', 'greater-equal', 'less', 'less-equal', 'equal', 'between'],
                    'type': 'str'
                },
                'value-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'choices': ['string', 'integer'], 'type': 'str'},
                'value1': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                'value2': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'report_chart_column_mapping'),
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
