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
module: fmgd_report_chart_xseries
short_description: X-series of chart.
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
  report_chart_xseries:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      caption:
        type: str
        description: X-series caption.
      caption_font_size:
        aliases: ['caption-font-size']
        type: int
        description: X-series caption font size.
      databind:
        type: str
        description: X-series value expression.
      font_size:
        aliases: ['font-size']
        type: int
        description: X-series label font size.
      is_category:
        aliases: ['is-category']
        type: str
        description: X-series represent category or not.
        choices: ['no', 'yes']
      label_angle:
        aliases: ['label-angle']
        type: str
        description: X-series label angle.
        choices: ['45-degree', 'vertical', 'horizontal']
      scale_direction:
        aliases: ['scale-direction']
        type: str
        description: Scale increase or decrease.
        choices: ['decrease', 'increase']
      scale_format:
        aliases: ['scale-format']
        type: str
        description: Date/time format.
        choices: ['YYYY-MM-DD-HH-MM', 'YYYY-MM-DD', 'HH', 'YYYY-MM', 'YYYY', 'HH-MM', 'MM-DD']
      scale_step:
        aliases: ['scale-step']
        type: int
        description: Scale step.
      scale_unit:
        aliases: ['scale-unit']
        type: str
        description: Scale unit.
        choices: ['minute', 'hour', 'day', 'month', 'year']
      unit:
        type: str
        description: X-series unit.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: X-series of chart.
      fortinet.fmgdevice.fmgd_report_chart_xseries:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        chart: <your own value>
        report_chart_xseries:
          # caption: <string>
          # caption_font_size: <integer>
          # databind: <string>
          # font_size: <integer>
          # is_category: <value in [no, yes]>
          # label_angle: <value in [45-degree, vertical, horizontal]>
          # scale_direction: <value in [decrease, increase]>
          # scale_format: <value in [YYYY-MM-DD-HH-MM, YYYY-MM-DD, HH, ...]>
          # scale_step: <integer>
          # scale_unit: <value in [minute, hour, day, ...]>
          # unit: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/x-series'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'chart': {'required': True, 'type': 'str'},
        'report_chart_xseries': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']],
            'options': {
                'caption': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                'caption-font-size': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'int'},
                'databind': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                'font-size': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'int'},
                'is-category': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'choices': ['no', 'yes'], 'type': 'str'},
                'label-angle': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'choices': ['45-degree', 'vertical', 'horizontal'], 'type': 'str'},
                'scale-direction': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'choices': ['decrease', 'increase'], 'type': 'str'},
                'scale-format': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']],
                    'choices': ['YYYY-MM-DD-HH-MM', 'YYYY-MM-DD', 'HH', 'YYYY-MM', 'YYYY', 'HH-MM', 'MM-DD'],
                    'type': 'str'
                },
                'scale-step': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'int'},
                'scale-unit': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'choices': ['minute', 'hour', 'day', 'month', 'year'], 'type': 'str'},
                'unit': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'report_chart_xseries'),
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
