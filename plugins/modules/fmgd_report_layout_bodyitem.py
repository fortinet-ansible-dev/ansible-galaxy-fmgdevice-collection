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
        choices: ['include-no-data', 'hide-title', 'show-caption']
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
        choices: ['hline', 'page-break', 'column-break', 'section-start']
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
        choices: ['text', 'heading1', 'heading2', 'heading3']
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
        choices: ['text', 'image', 'chart', 'misc']
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
        choices: ['bullet', 'numbered']
      hide:
        type: str
        description: Enable/disable hide item in report.
        choices: ['disable', 'enable']
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
  gather_facts: false
  tasks:
    - name: Configure report body item.
      fortinet.fmgdevice.fmgd_report_layout_bodyitem:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        layout: <your own value>
        state: present # <value in [present, absent]>
        report_layout_bodyitem:
          id: 0 # Required variable, integer
          # chart: <list or string>
          # chart_options: ["include-no-data", "hide-title", "show-caption"]
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
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'layout': {'required': True, 'type': 'str'},
        'report_layout_bodyitem': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'chart': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'chart-options': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['include-no-data', 'hide-title', 'show-caption'],
                    'elements': 'str'
                },
                'content': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'img-src': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'misc-component': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['hline', 'page-break', 'column-break', 'section-start'],
                    'type': 'str'
                },
                'parameters': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'value': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'style': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'text-component': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['text', 'heading1', 'heading2', 'heading3'],
                    'type': 'str'
                },
                'title': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'top-n': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['text', 'image', 'chart', 'misc'], 'type': 'str'},
                'table-caption-style': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'list', 'elements': 'str'},
                'list': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']],
                    'type': 'list',
                    'options': {
                        'content': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'table-column-widths': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                'table-odd-row-style': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'list', 'elements': 'str'},
                'table-even-row-style': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'list', 'elements': 'str'},
                'column': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'int'},
                'drill-down-types': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                'list-component': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'choices': ['bullet', 'numbered'], 'type': 'str'},
                'hide': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'drill-down-items': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                'table-head-style': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'report_layout_bodyitem'),
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
