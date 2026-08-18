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
module: fmgd_report_chart_yseries
short_description: Y-series of chart.
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
  chart:
    description: The parameter (chart) in requested url.
    type: str
    required: true
  report_chart_yseries:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      caption:
        type: str
        description: Y-series caption.
      caption_font_size:
        aliases: ['caption-font-size']
        type: int
        description: Y-series caption font size.
      databind:
        type: str
        description: Y-series value expression.
      extra_databind:
        aliases: ['extra-databind']
        type: str
        description: Extra Y-series value.
      extra_y:
        aliases: ['extra-y']
        type: str
        description: Allow another Y-series value
        choices: ['disable', 'enable']
      extra_y_legend:
        aliases: ['extra-y-legend']
        type: str
        description: Extra Y-series legend type/name.
      font_size:
        aliases: ['font-size']
        type: int
        description: Y-series label font size.
      group:
        type: str
        description: Y-series group option.
      label_angle:
        aliases: ['label-angle']
        type: str
        description: Y-series label angle.
        choices: ['45-degree', 'vertical', 'horizontal']
      unit:
        type: str
        description: Y-series unit.
      y_legend:
        aliases: ['y-legend']
        type: str
        description: First Y-series legend type/name.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Y-series of chart.
      fortinet.fmgdevice.fmgd_report_chart_yseries:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        chart: <your own value>
        report_chart_yseries:
          # caption: <string>
          # caption_font_size: <integer>
          # databind: <string>
          # extra_databind: <string>
          # extra_y: <value in [disable, enable]>
          # extra_y_legend: <string>
          # font_size: <integer>
          # group: <string>
          # label_angle: <value in [45-degree, vertical, horizontal]>
          # unit: <string>
          # y_legend: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/y-series'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'chart': {'required': True, 'type': 'str'},
        'report_chart_yseries': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']],
            'options': {
                'caption': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                'caption-font-size': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'int'},
                'databind': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                'extra-databind': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                'extra-y': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'extra-y-legend': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                'font-size': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'int'},
                'group': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                'label-angle': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'choices': ['45-degree', 'vertical', 'horizontal'], 'type': 'str'},
                'unit': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                'y-legend': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'report_chart_yseries'),
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
