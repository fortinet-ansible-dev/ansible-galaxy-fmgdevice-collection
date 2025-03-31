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
module: fmgd_report_chart
short_description: Report chart widget configuration.
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
    report_chart:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            background:
                type: str
                description: Chart background.
            category:
                type: str
                description: Category.
                choices:
                    - 'traffic'
                    - 'event'
                    - 'virus'
                    - 'webfilter'
                    - 'attack'
                    - 'spam'
                    - 'dlp'
                    - 'app-ctrl'
                    - 'misc'
                    - 'vulnerability'
            category_series:
                aliases: ['category-series']
                type: dict
                description: Category series.
                suboptions:
                    databind:
                        type: str
                        description: Category series value expression.
                    font_size:
                        aliases: ['font-size']
                        type: int
                        description: Font size of category-series title.
            color_palette:
                aliases: ['color-palette']
                type: list
                elements: str
                description: Color palette
            column:
                type: list
                elements: dict
                description: Column.
                suboptions:
                    detail_unit:
                        aliases: ['detail-unit']
                        type: str
                        description: Detail unit of column.
                    detail_value:
                        aliases: ['detail-value']
                        type: str
                        description: Detail value of column.
                    footer_unit:
                        aliases: ['footer-unit']
                        type: str
                        description: Footer unit of column.
                    footer_value:
                        aliases: ['footer-value']
                        type: str
                        description: Footer value of column.
                    header_value:
                        aliases: ['header-value']
                        type: str
                        description: Display name of table header.
                    id:
                        type: int
                        description: ID.
                    mapping:
                        type: list
                        elements: dict
                        description: Mapping.
                        suboptions:
                            displayname:
                                type: str
                                description: Display name.
                            id:
                                type: int
                                description: Id.
                            op:
                                type: str
                                description: Comparision operater.
                                choices:
                                    - 'none'
                                    - 'greater'
                                    - 'greater-equal'
                                    - 'less'
                                    - 'less-equal'
                                    - 'equal'
                                    - 'between'
                            value_type:
                                aliases: ['value-type']
                                type: str
                                description: Value type.
                                choices:
                                    - 'string'
                                    - 'integer'
                            value1:
                                type: str
                                description: Value 1.
                            value2:
                                type: str
                                description: Value 2.
            comments:
                type: str
                description: Comment.
            dataset:
                type: list
                elements: str
                description: Bind dataset to chart.
            dimension:
                type: str
                description: Dimension.
                choices:
                    - '2D'
                    - '3D'
            drill_down_charts:
                aliases: ['drill-down-charts']
                type: list
                elements: dict
                description: Drill down charts.
                suboptions:
                    chart_name:
                        aliases: ['chart-name']
                        type: str
                        description: Drill down chart name.
                    id:
                        type: int
                        description: Drill down chart ID.
                    status:
                        type: str
                        description: Enable/disable this drill down chart.
                        choices:
                            - 'disable'
                            - 'enable'
            favorite:
                type: str
                description: Favorite.
                choices:
                    - 'no'
                    - 'yes'
            graph_type:
                aliases: ['graph-type']
                type: str
                description: Graph type.
                choices:
                    - 'bar'
                    - 'line'
                    - 'pie'
                    - 'none'
                    - 'flow'
            legend:
                type: str
                description: Enable/Disable Legend area.
                choices:
                    - 'disable'
                    - 'enable'
            legend_font_size:
                aliases: ['legend-font-size']
                type: int
                description: Font size of legend area.
            name:
                type: str
                description: Chart Widget Name
                required: true
            period:
                type: str
                description: Time period.
                choices:
                    - 'last24h'
                    - 'last7d'
            policy:
                type: int
                description: Policy.
            style:
                type: str
                description: Style.
                choices:
                    - 'auto'
                    - 'manual'
            title:
                type: str
                description: Chart title.
            title_font_size:
                aliases: ['title-font-size']
                type: int
                description: Font size of chart title.
            type:
                type: str
                description: Chart type.
                choices:
                    - 'graph'
                    - 'table'
            value_series:
                aliases: ['value-series']
                type: dict
                description: Value series.
                suboptions:
                    databind:
                        type: str
                        description: Value series value expression.
            x_series:
                aliases: ['x-series']
                type: dict
                description: X series.
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
            y_series:
                aliases: ['y-series']
                type: dict
                description: Y series.
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
                        choices:
                            - 'disable'
                            - 'enable'
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
                        choices:
                            - '45-degree'
                            - 'vertical'
                            - 'horizontal'
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
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Report chart widget configuration.
      fortinet.fmgdevice.fmgd_report_chart:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        report_chart:
          name: "your value" # Required variable, string
          # background: <string>
          # category: <value in [traffic, event, virus, ...]>
          # category_series:
          #   databind: <string>
          #   font_size: <integer>
          # color_palette: <list or string>
          # column:
          #   - detail_unit: <string>
          #     detail_value: <string>
          #     footer_unit: <string>
          #     footer_value: <string>
          #     header_value: <string>
          #     id: <integer>
          #     mapping:
          #       - displayname: <string>
          #         id: <integer>
          #         op: <value in [none, greater, greater-equal, ...]>
          #         value_type: <value in [string, integer]>
          #         value1: <string>
          #         value2: <string>
          # comments: <string>
          # dataset: <list or string>
          # dimension: <value in [2D, 3D]>
          # drill_down_charts:
          #   - chart_name: <string>
          #     id: <integer>
          #     status: <value in [disable, enable]>
          # favorite: <value in [no, yes]>
          # graph_type: <value in [bar, line, pie, ...]>
          # legend: <value in [disable, enable]>
          # legend_font_size: <integer>
          # period: <value in [last24h, last7d]>
          # policy: <integer>
          # style: <value in [auto, manual]>
          # title: <string>
          # title_font_size: <integer>
          # type: <value in [graph, table]>
          # value_series:
          #   databind: <string>
          # x_series:
          #   caption: <string>
          #   caption_font_size: <integer>
          #   databind: <string>
          #   font_size: <integer>
          #   is_category: <value in [no, yes]>
          #   label_angle: <value in [45-degree, vertical, horizontal]>
          #   scale_direction: <value in [decrease, increase]>
          #   scale_format: <value in [YYYY-MM-DD-HH-MM, YYYY-MM-DD, HH, ...]>
          #   scale_step: <integer>
          #   scale_unit: <value in [minute, hour, day, ...]>
          #   unit: <string>
          # y_series:
          #   caption: <string>
          #   caption_font_size: <integer>
          #   databind: <string>
          #   extra_databind: <string>
          #   extra_y: <value in [disable, enable]>
          #   extra_y_legend: <string>
          #   font_size: <integer>
          #   group: <string>
          #   label_angle: <value in [45-degree, vertical, horizontal]>
          #   unit: <string>
          #   y_legend: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/report/chart'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'report_chart': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'background': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'category': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['traffic', 'event', 'virus', 'webfilter', 'attack', 'spam', 'dlp', 'app-ctrl', 'misc', 'vulnerability'],
                    'type': 'str'
                },
                'category-series': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'databind': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'font-size': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    }
                },
                'color-palette': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'column': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'detail-unit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'detail-value': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'footer-unit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'footer-value': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'header-value': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'mapping': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'displayname': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'op': {
                                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                                    'choices': ['none', 'greater', 'greater-equal', 'less', 'less-equal', 'equal', 'between'],
                                    'type': 'str'
                                },
                                'value-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['string', 'integer'], 'type': 'str'},
                                'value1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                                'value2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        }
                    },
                    'elements': 'dict'
                },
                'comments': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dataset': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dimension': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['2D', '3D'], 'type': 'str'},
                'drill-down-charts': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'chart-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'favorite': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                'graph-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['bar', 'line', 'pie', 'none', 'flow'], 'type': 'str'},
                'legend': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'legend-font-size': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'period': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['last24h', 'last7d'], 'type': 'str'},
                'policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'style': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['auto', 'manual'], 'type': 'str'},
                'title': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'title-font-size': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['graph', 'table'], 'type': 'str'},
                'value-series': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {'databind': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}}
                },
                'x-series': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
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
                        'scale-unit': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['minute', 'hour', 'day', 'month', 'year'],
                            'type': 'str'
                        },
                        'unit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    }
                },
                'y-series': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'caption': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'caption-font-size': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'databind': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'extra-databind': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'extra-y': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'extra-y-legend': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'font-size': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'label-angle': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['45-degree', 'vertical', 'horizontal'], 'type': 'str'},
                        'unit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'y-legend': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    }
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'report_chart'),
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
