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
module: fmgd_system_theme
short_description: Configure custom gui themes.
version_added: "1.2.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_theme:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      accent_color:
        aliases: ['accent-color']
        type: str
        description: Hexidecimal color code for the accent color.
      banner_msg:
        aliases: ['banner-msg']
        type: str
        description: Optional message to appear on the fortigate header.
      banner_msg_severity:
        aliases: ['banner-msg-severity']
        type: str
        description: Severity color of the banner message.
        choices: ['info', 'warning', 'critical']
      base_theme:
        aliases: ['base-theme']
        type: str
        description: Base theme that will be used as a template.
        choices: ['light', 'dark']
      border_radius:
        aliases: ['border-radius']
        type: str
        description: Enable/disable border radius.
        choices: ['disable', 'enable']
      call_to_action_color:
        aliases: ['call-to-action-color']
        type: str
        description: Hexidecimal color code for the call to action color.
      font:
        type: str
        description: Font family.
        choices: ['lato', 'inter']
      font_weight:
        aliases: ['font-weight']
        type: str
        description: Font weight.
        choices: ['light', 'standard']
      header_color:
        aliases: ['header-color']
        type: str
        description: Hexidecimal color code for the header color.
      name:
        type: str
        description: Custom theme name.
        required: true
      nav_color:
        aliases: ['nav-color']
        type: str
        description: Color of the navigation bar.
        choices: ['light', 'dark', 'gray']
      nav_style:
        aliases: ['nav-style']
        type: str
        description: Navigation bar style.
        choices: ['standard', 'full-height']
      selected_color:
        aliases: ['selected-color']
        type: str
        description: Hexidecimal color code for the selected color.
      table_style:
        aliases: ['table-style']
        type: str
        description: Table style.
        choices: ['fill', 'float']
      theme_template:
        aliases: ['theme-template']
        type: str
        description: Theme template that will be used in place of the base theme.
        choices: ['melongene', 'mariner', 'neutrino', 'jade', 'graphite', 'dark-matter', 'onyx',
                  'eclipse', 'retro', 'jet-stream', 'security-fabric', 'none']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure custom gui themes.
      fortinet.fmgdevice.fmgd_system_theme:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        system_theme:
          name: "your value" # Required variable, string
          # accent_color: <string>
          # banner_msg: <string>
          # banner_msg_severity: <value in [info, warning, critical]>
          # base_theme: <value in [light, dark]>
          # border_radius: <value in [disable, enable]>
          # call_to_action_color: <string>
          # font: <value in [lato, inter]>
          # font_weight: <value in [light, standard]>
          # header_color: <string>
          # nav_color: <value in [light, dark, gray]>
          # nav_style: <value in [standard, full-height]>
          # selected_color: <string>
          # table_style: <value in [fill, float]>
          # theme_template: <value in [melongene, mariner, neutrino, ...]>
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
        '/pm/config/device/{device}/global/system/theme'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_theme': {
            'type': 'dict', 'v_range': [['8.0.0', '']],
            'options': {
                'accent-color': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'banner-msg': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'banner-msg-severity': {'v_range': [['8.0.0', '']], 'choices': ['info', 'warning', 'critical'], 'type': 'str'},
                'base-theme': {'v_range': [['8.0.0', '']], 'choices': ['light', 'dark'], 'type': 'str'},
                'border-radius': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'call-to-action-color': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'font': {'v_range': [['8.0.0', '']], 'choices': ['lato', 'inter'], 'type': 'str'},
                'font-weight': {'v_range': [['8.0.0', '']], 'choices': ['light', 'standard'], 'type': 'str'},
                'header-color': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'name': {'v_range': [['8.0.0', '']], 'required': True, 'type': 'str'},
                'nav-color': {'v_range': [['8.0.0', '']], 'choices': ['light', 'dark', 'gray'], 'type': 'str'},
                'nav-style': {'v_range': [['8.0.0', '']], 'choices': ['standard', 'full-height'], 'type': 'str'},
                'selected-color': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'table-style': {'v_range': [['8.0.0', '']], 'choices': ['fill', 'float'], 'type': 'str'},
                'theme-template': {
                    'v_range': [['8.0.0', '']],
                    'choices': [
                        'melongene', 'mariner', 'neutrino', 'jade', 'graphite', 'dark-matter', 'onyx', 'eclipse', 'retro', 'jet-stream',
                        'security-fabric', 'none'
                    ],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_theme'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
