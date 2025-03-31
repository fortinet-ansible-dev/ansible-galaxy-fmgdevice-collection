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
module: fmgd_report_style
short_description: Report style configuration.
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
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
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
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
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
    report_style:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            align:
                type: str
                description: Alignment.
                choices:
                    - 'left'
                    - 'center'
                    - 'right'
                    - 'justify'
            bg_color:
                aliases: ['bg-color']
                type: str
                description: Background color.
            border_bottom:
                aliases: ['border-bottom']
                type: str
                description: Border bottom.
            border_left:
                aliases: ['border-left']
                type: str
                description: Border left.
            border_right:
                aliases: ['border-right']
                type: str
                description: Border right.
            border_top:
                aliases: ['border-top']
                type: str
                description: Border top.
            column_gap:
                aliases: ['column-gap']
                type: str
                description: Column gap.
            column_span:
                aliases: ['column-span']
                type: str
                description: Column span.
                choices:
                    - 'none'
                    - 'all'
            fg_color:
                aliases: ['fg-color']
                type: str
                description: Foreground color.
            font_family:
                aliases: ['font-family']
                type: str
                description: Font family.
                choices:
                    - 'Verdana'
                    - 'Arial'
                    - 'Helvetica'
                    - 'Courier'
                    - 'Times'
            font_size:
                aliases: ['font-size']
                type: str
                description: Font size.
            font_style:
                aliases: ['font-style']
                type: str
                description: Font style.
                choices:
                    - 'normal'
                    - 'italic'
            font_weight:
                aliases: ['font-weight']
                type: str
                description: Font weight.
                choices:
                    - 'normal'
                    - 'bold'
            height:
                type: str
                description: Height.
            line_height:
                aliases: ['line-height']
                type: str
                description: Text line height.
            margin_bottom:
                aliases: ['margin-bottom']
                type: str
                description: Margin bottom.
            margin_left:
                aliases: ['margin-left']
                type: str
                description: Margin left.
            margin_right:
                aliases: ['margin-right']
                type: str
                description: Margin right.
            margin_top:
                aliases: ['margin-top']
                type: str
                description: Margin top.
            name:
                type: str
                description: Report style name.
                required: true
            options:
                type: list
                elements: str
                description: Report style options.
                choices:
                    - 'font'
                    - 'text'
                    - 'color'
                    - 'align'
                    - 'size'
                    - 'margin'
                    - 'border'
                    - 'padding'
                    - 'column'
            padding_bottom:
                aliases: ['padding-bottom']
                type: str
                description: Padding bottom.
            padding_left:
                aliases: ['padding-left']
                type: str
                description: Padding left.
            padding_right:
                aliases: ['padding-right']
                type: str
                description: Padding right.
            padding_top:
                aliases: ['padding-top']
                type: str
                description: Padding top.
            width:
                type: str
                description: Width.
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
    - name: Report style configuration.
      fortinet.fmgdevice.fmgd_report_style:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        report_style:
          name: "your value" # Required variable, string
          # align: <value in [left, center, right, ...]>
          # bg_color: <string>
          # border_bottom: <string>
          # border_left: <string>
          # border_right: <string>
          # border_top: <string>
          # column_gap: <string>
          # column_span: <value in [none, all]>
          # fg_color: <string>
          # font_family: <value in [Verdana, Arial, Helvetica, ...]>
          # font_size: <string>
          # font_style: <value in [normal, italic]>
          # font_weight: <value in [normal, bold]>
          # height: <string>
          # line_height: <string>
          # margin_bottom: <string>
          # margin_left: <string>
          # margin_right: <string>
          # margin_top: <string>
          # options:
          #   - "font"
          #   - "text"
          #   - "color"
          #   - "align"
          #   - "size"
          #   - "margin"
          #   - "border"
          #   - "padding"
          #   - "column"
          # padding_bottom: <string>
          # padding_left: <string>
          # padding_right: <string>
          # padding_top: <string>
          # width: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/report/style'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'report_style': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'align': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['left', 'center', 'right', 'justify'], 'type': 'str'},
                'bg-color': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'border-bottom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'border-left': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'border-right': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'border-top': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'column-gap': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'column-span': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'all'], 'type': 'str'},
                'fg-color': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'font-family': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['Verdana', 'Arial', 'Helvetica', 'Courier', 'Times'],
                    'type': 'str'
                },
                'font-size': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'font-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['normal', 'italic'], 'type': 'str'},
                'font-weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['normal', 'bold'], 'type': 'str'},
                'height': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'line-height': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'margin-bottom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'margin-left': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'margin-right': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'margin-top': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'options': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['font', 'text', 'color', 'align', 'size', 'margin', 'border', 'padding', 'column'],
                    'elements': 'str'
                },
                'padding-bottom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'padding-left': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'padding-right': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'padding-top': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'width': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'report_style'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
