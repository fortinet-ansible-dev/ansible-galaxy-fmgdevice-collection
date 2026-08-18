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
module: fmgd_report_layout_page
short_description: Configure report page.
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
  layout:
    description: The parameter (layout) in requested url.
    type: str
    required: true
  report_layout_page:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      column_break_before:
        aliases: ['column-break-before']
        type: list
        elements: str
        description: Report page auto column break before heading.
        choices: ['heading1', 'heading2', 'heading3']
      footer:
        type: dict
        description: Footer.
        suboptions:
          footer_item:
            aliases: ['footer-item']
            type: list
            elements: dict
            description: Footer item.
            suboptions:
              content:
                type: str
                description: Report item text content.
              description:
                type: str
                description: Description.
              id:
                type: int
                description: Report item ID.
              img_src:
                aliases: ['img-src']
                type: str
                description: Report item image file name.
              style:
                type: list
                elements: str
                description: Report item style.
              type:
                type: str
                description: Report item type.
                choices: ['text', 'image']
          style:
            type: list
            elements: str
            description: Report footer style.
      header:
        type: dict
        description: Header.
        suboptions:
          header_item:
            aliases: ['header-item']
            type: list
            elements: dict
            description: Header item.
            suboptions:
              content:
                type: str
                description: Report item text content.
              description:
                type: str
                description: Description.
              id:
                type: int
                description: Report item ID.
              img_src:
                aliases: ['img-src']
                type: str
                description: Report item image file name.
              style:
                type: list
                elements: str
                description: Report item style.
              type:
                type: str
                description: Report item type.
                choices: ['text', 'image']
          style:
            type: list
            elements: str
            description: Report header style.
      options:
        type: list
        elements: str
        description: Report page options.
        choices: ['header-on-first-page', 'footer-on-first-page']
      page_break_before:
        aliases: ['page-break-before']
        type: list
        elements: str
        description: Report page auto page break before heading.
        choices: ['heading1', 'heading2', 'heading3']
      paper:
        type: str
        description: Report page paper.
        choices: ['a4', 'letter']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure report page.
      fortinet.fmgdevice.fmgd_report_layout_page:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        layout: <your own value>
        report_layout_page:
          # column_break_before: ["heading1", "heading2", "heading3"]
          # footer:
          #   footer_item:
          #     - content: <string>
          #       description: <string>
          #       id: <integer>
          #       img_src: <string>
          #       style: <list or string>
          #       type: <value in [text, image]>
          #   style: <list or string>
          # header:
          #   header_item:
          #     - content: <string>
          #       description: <string>
          #       id: <integer>
          #       img_src: <string>
          #       style: <list or string>
          #       type: <value in [text, image]>
          #   style: <list or string>
          # options: ["header-on-first-page", "footer-on-first-page"]
          # page_break_before: ["heading1", "heading2", "heading3"]
          # paper: <value in [a4, letter]>
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
        '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/page'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'layout': {'required': True, 'type': 'str'},
        'report_layout_page': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'column-break-before': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['heading1', 'heading2', 'heading3'],
                    'elements': 'str'
                },
                'footer': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'footer-item': {
                            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'content': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                                'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                                'img-src': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                                'style': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                                'type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['text', 'image'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'style': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    }
                },
                'header': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'header-item': {
                            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'content': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                                'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                                'img-src': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                                'style': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                                'type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['text', 'image'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'style': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    }
                },
                'options': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['header-on-first-page', 'footer-on-first-page'],
                    'elements': 'str'
                },
                'page-break-before': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['heading1', 'heading2', 'heading3'],
                    'elements': 'str'
                },
                'paper': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['a4', 'letter'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'report_layout_page'),
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
