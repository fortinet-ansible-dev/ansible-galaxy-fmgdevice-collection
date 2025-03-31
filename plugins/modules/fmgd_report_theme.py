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
module: fmgd_report_theme
short_description: Report themes configuration
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
    report_theme:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            bullet_list_style:
                aliases: ['bullet-list-style']
                type: list
                elements: str
                description: Bullet list style.
            column_count:
                aliases: ['column-count']
                type: str
                description: Report page column count.
                choices:
                    - '1'
                    - '2'
                    - '3'
            default_html_style:
                aliases: ['default-html-style']
                type: list
                elements: str
                description: Default HTML report style.
            default_pdf_style:
                aliases: ['default-pdf-style']
                type: list
                elements: str
                description: Default PDF report style.
            graph_chart_style:
                aliases: ['graph-chart-style']
                type: list
                elements: str
                description: Graph chart style.
            heading1_style:
                aliases: ['heading1-style']
                type: list
                elements: str
                description: Report heading style.
            heading2_style:
                aliases: ['heading2-style']
                type: list
                elements: str
                description: Report heading style.
            heading3_style:
                aliases: ['heading3-style']
                type: list
                elements: str
                description: Report heading style.
            heading4_style:
                aliases: ['heading4-style']
                type: list
                elements: str
                description: Report heading style.
            hline_style:
                aliases: ['hline-style']
                type: list
                elements: str
                description: Horizontal line style.
            image_style:
                aliases: ['image-style']
                type: list
                elements: str
                description: Image style.
            name:
                type: str
                description: Report theme name.
                required: true
            normal_text_style:
                aliases: ['normal-text-style']
                type: list
                elements: str
                description: Normal text style.
            numbered_list_style:
                aliases: ['numbered-list-style']
                type: list
                elements: str
                description: Numbered list style.
            page_footer_style:
                aliases: ['page-footer-style']
                type: list
                elements: str
                description: Report page footer style.
            page_header_style:
                aliases: ['page-header-style']
                type: list
                elements: str
                description: Report page header style.
            page_orient:
                aliases: ['page-orient']
                type: str
                description: Report page orientation.
                choices:
                    - 'portrait'
                    - 'landscape'
            page_style:
                aliases: ['page-style']
                type: list
                elements: str
                description: Report page style.
            report_subtitle_style:
                aliases: ['report-subtitle-style']
                type: list
                elements: str
                description: Report subtitle style.
            report_title_style:
                aliases: ['report-title-style']
                type: list
                elements: str
                description: Report title style.
            table_chart_caption_style:
                aliases: ['table-chart-caption-style']
                type: list
                elements: str
                description: Table chart caption style.
            table_chart_even_row_style:
                aliases: ['table-chart-even-row-style']
                type: list
                elements: str
                description: Table chart even row style.
            table_chart_head_style:
                aliases: ['table-chart-head-style']
                type: list
                elements: str
                description: Table chart head row style.
            table_chart_odd_row_style:
                aliases: ['table-chart-odd-row-style']
                type: list
                elements: str
                description: Table chart odd row style.
            table_chart_style:
                aliases: ['table-chart-style']
                type: list
                elements: str
                description: Table chart style.
            toc_heading1_style:
                aliases: ['toc-heading1-style']
                type: list
                elements: str
                description: Table of contents heading style.
            toc_heading2_style:
                aliases: ['toc-heading2-style']
                type: list
                elements: str
                description: Table of contents heading style.
            toc_heading3_style:
                aliases: ['toc-heading3-style']
                type: list
                elements: str
                description: Table of contents heading style.
            toc_heading4_style:
                aliases: ['toc-heading4-style']
                type: list
                elements: str
                description: Table of contents heading style.
            toc_title_style:
                aliases: ['toc-title-style']
                type: list
                elements: str
                description: Table of contents title style.
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
    - name: Report themes configuration
      fortinet.fmgdevice.fmgd_report_theme:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        report_theme:
          name: "your value" # Required variable, string
          # bullet_list_style: <list or string>
          # column_count: <value in [1, 2, 3]>
          # default_html_style: <list or string>
          # default_pdf_style: <list or string>
          # graph_chart_style: <list or string>
          # heading1_style: <list or string>
          # heading2_style: <list or string>
          # heading3_style: <list or string>
          # heading4_style: <list or string>
          # hline_style: <list or string>
          # image_style: <list or string>
          # normal_text_style: <list or string>
          # numbered_list_style: <list or string>
          # page_footer_style: <list or string>
          # page_header_style: <list or string>
          # page_orient: <value in [portrait, landscape]>
          # page_style: <list or string>
          # report_subtitle_style: <list or string>
          # report_title_style: <list or string>
          # table_chart_caption_style: <list or string>
          # table_chart_even_row_style: <list or string>
          # table_chart_head_style: <list or string>
          # table_chart_odd_row_style: <list or string>
          # table_chart_style: <list or string>
          # toc_heading1_style: <list or string>
          # toc_heading2_style: <list or string>
          # toc_heading3_style: <list or string>
          # toc_heading4_style: <list or string>
          # toc_title_style: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/report/theme'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'report_theme': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'bullet-list-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'column-count': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['1', '2', '3'], 'type': 'str'},
                'default-html-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'default-pdf-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'graph-chart-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'heading1-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'heading2-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'heading3-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'heading4-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'hline-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'image-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'normal-text-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'numbered-list-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'page-footer-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'page-header-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'page-orient': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['portrait', 'landscape'], 'type': 'str'},
                'page-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'report-subtitle-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'report-title-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'table-chart-caption-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'table-chart-even-row-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'table-chart-head-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'table-chart-odd-row-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'table-chart-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'toc-heading1-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'toc-heading2-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'toc-heading3-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'toc-heading4-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'toc-title-style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'report_theme'),
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
