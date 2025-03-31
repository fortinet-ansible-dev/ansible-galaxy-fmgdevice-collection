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
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
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
                choices:
                    - 'no'
                    - 'yes'
            label_angle:
                aliases: ['label-angle']
                type: str
                description: X-series label angle.
                choices:
                    - '45-degree'
                    - 'vertical'
                    - 'horizontal'
            scale_direction:
                aliases: ['scale-direction']
                type: str
                description: Scale increase or decrease.
                choices:
                    - 'decrease'
                    - 'increase'
            scale_format:
                aliases: ['scale-format']
                type: str
                description: Date/time format.
                choices:
                    - 'YYYY-MM-DD-HH-MM'
                    - 'YYYY-MM-DD'
                    - 'HH'
                    - 'YYYY-MM'
                    - 'YYYY'
                    - 'HH-MM'
                    - 'MM-DD'
            scale_step:
                aliases: ['scale-step']
                type: int
                description: Scale step.
            scale_unit:
                aliases: ['scale-unit']
                type: str
                description: Scale unit.
                choices:
                    - 'minute'
                    - 'hour'
                    - 'day'
                    - 'month'
                    - 'year'
            unit:
                type: str
                description: X-series unit.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: X-series of chart.
      fortinet.fmgdevice.fmgd_report_chart_xseries:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
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
    url_params = ['device', 'vdom', 'chart']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'chart': {'required': True, 'type': 'str'},
        'report_chart_xseries': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'caption': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'caption-font-size': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'databind': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'font-size': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'is-category': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                'label-angle': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['45-degree', 'vertical', 'horizontal'], 'type': 'str'},
                'scale-direction': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['decrease', 'increase'], 'type': 'str'},
                'scale-format': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['YYYY-MM-DD-HH-MM', 'YYYY-MM-DD', 'HH', 'YYYY-MM', 'YYYY', 'HH-MM', 'MM-DD'],
                    'type': 'str'
                },
                'scale-step': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'scale-unit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['minute', 'hour', 'day', 'month', 'year'], 'type': 'str'},
                'unit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'report_chart_xseries'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
