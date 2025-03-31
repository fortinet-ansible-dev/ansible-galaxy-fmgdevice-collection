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
module: fmgd_report_layout_bodyitem
short_description: Configure report body item.
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
    layout:
        description: The parameter (layout) in requested url.
        type: str
        required: true
    report_layout_bodyitem:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            chart:
                type: list
                elements: str
                description: Report item chart name.
            chart_options:
                aliases: ['chart-options']
                type: list
                elements: str
                description: Report chart options.
                choices:
                    - 'include-no-data'
                    - 'hide-title'
                    - 'show-caption'
            content:
                type: str
                description: Report item text content.
            description:
                type: str
                description: Description.
            id:
                type: int
                description: Report item ID.
                required: true
            img_src:
                aliases: ['img-src']
                type: str
                description: Report item image file name.
            misc_component:
                aliases: ['misc-component']
                type: str
                description: Report item miscellaneous component.
                choices:
                    - 'hline'
                    - 'page-break'
                    - 'column-break'
                    - 'section-start'
            parameters:
                type: list
                elements: dict
                description: Parameters.
                suboptions:
                    id:
                        type: int
                        description: ID.
                    name:
                        type: str
                        description: Field name that match field of parameters defined in dataset.
                    value:
                        type: str
                        description: Value to replace corresponding field of parameters defined in dataset.
            style:
                type: list
                elements: str
                description: Report item style.
            text_component:
                aliases: ['text-component']
                type: str
                description: Report item text component.
                choices:
                    - 'text'
                    - 'heading1'
                    - 'heading2'
                    - 'heading3'
            title:
                type: str
                description: Report section title.
            top_n:
                aliases: ['top-n']
                type: int
                description: Value of top.
            type:
                type: str
                description: Report item type.
                choices:
                    - 'text'
                    - 'image'
                    - 'chart'
                    - 'misc'
            table_caption_style:
                aliases: ['table-caption-style']
                type: list
                elements: str
                description: Table chart caption style.
            list:
                type: list
                elements: dict
                description: List.
                suboptions:
                    content:
                        type: str
                        description: List entry content.
                    id:
                        type: int
                        description: List entry ID.
            table_column_widths:
                aliases: ['table-column-widths']
                type: str
                description: Report item table column widths.
            table_odd_row_style:
                aliases: ['table-odd-row-style']
                type: list
                elements: str
                description: Table chart odd row style.
            table_even_row_style:
                aliases: ['table-even-row-style']
                type: list
                elements: str
                description: Table chart even row style.
            column:
                type: int
                description: Report section column number.
            drill_down_types:
                aliases: ['drill-down-types']
                type: str
                description: Control whether keys from the parent being combined or not.
            list_component:
                aliases: ['list-component']
                type: str
                description: Report item list component.
                choices:
                    - 'bullet'
                    - 'numbered'
            hide:
                type: str
                description: Enable/disable hide item in report.
                choices:
                    - 'disable'
                    - 'enable'
            drill_down_items:
                aliases: ['drill-down-items']
                type: str
                description: Control how drill down charts are shown.
            table_head_style:
                aliases: ['table-head-style']
                type: list
                elements: str
                description: Table chart head style.
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
    - name: Configure report body item.
      fortinet.fmgdevice.fmgd_report_layout_bodyitem:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        layout: <your own value>
        state: present # <value in [present, absent]>
        report_layout_bodyitem:
          id: 0 # Required variable, integer
          # chart: <list or string>
          # chart_options:
          #   - "include-no-data"
          #   - "hide-title"
          #   - "show-caption"
          # content: <string>
          # description: <string>
          # img_src: <string>
          # misc_component: <value in [hline, page-break, column-break, ...]>
          # parameters:
          #   - id: <integer>
          #     name: <string>
          #     value: <string>
          # style: <list or string>
          # text_component: <value in [text, heading1, heading2, ...]>
          # title: <string>
          # top_n: <integer>
          # type: <value in [text, image, chart, ...]>
          # table_caption_style: <list or string>
          # list:
          #   - content: <string>
          #     id: <integer>
          # table_column_widths: <string>
          # table_odd_row_style: <list or string>
          # table_even_row_style: <list or string>
          # column: <integer>
          # drill_down_types: <string>
          # list_component: <value in [bullet, numbered]>
          # hide: <value in [disable, enable]>
          # drill_down_items: <string>
          # table_head_style: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/body-item'
    ]
    url_params = ['device', 'vdom', 'layout']
    module_primary_key = 'id'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'layout': {'required': True, 'type': 'str'},
        'report_layout_bodyitem': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'chart': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'chart-options': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['include-no-data', 'hide-title', 'show-caption'],
                    'elements': 'str'
                },
                'content': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'description': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'img-src': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'misc-component': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['hline', 'page-break', 'column-break', 'section-start'],
                    'type': 'str'
                },
                'parameters': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'value': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'text-component': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['text', 'heading1', 'heading2', 'heading3'], 'type': 'str'},
                'title': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'top-n': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['text', 'image', 'chart', 'misc'], 'type': 'str'},
                'table-caption-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'list': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'content': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'table-column-widths': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'table-odd-row-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'table-even-row-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'column': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'drill-down-types': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'list-component': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['bullet', 'numbered'], 'type': 'str'},
                'hide': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'drill-down-items': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'table-head-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'report_layout_bodyitem'),
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
