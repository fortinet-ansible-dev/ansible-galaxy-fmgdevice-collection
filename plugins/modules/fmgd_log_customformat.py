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
module: fmgd_log_customformat
short_description: Configure custom log format.
version_added: "1.2.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  log_customformat:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      empty_value_indicator:
        aliases: ['empty-value-indicator']
        type: str
        description: A character to indicate log field is empty.
      field_exclusion_list:
        aliases: ['field-exclusion-list']
        type: list
        elements: str
        description: Log fields to exclude in the log.
      log_templates:
        aliases: ['log-templates']
        type: list
        elements: dict
        description: Log templates.
        suboptions:
          category:
            type: str
            description: Log category.
            choices: ['traffic', 'event', 'virus', 'webfilter', 'attack', 'spam', 'voip', 'dlp',
                      'app-ctrl', 'anomaly', 'waf', 'gtp', 'dns', 'ssh', 'ssl', 'file-filter',
                      'icap', 'virtual-patch', 'debug']
          name:
            type: str
            description: Template name string.
          subtypes:
            type: list
            elements: str
            description: Log subtypes to apply template to.
          template:
            type: str
            description: Log template string.
      name:
        type: str
        description: Format name string.
        required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure custom log format.
      fortinet.fmgdevice.fmgd_log_customformat:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        log_customformat:
          name: "your value" # Required variable, string
          # empty_value_indicator: <string>
          # field_exclusion_list: <list or string>
          # log_templates:
          #   - category: <value in [traffic, event, virus, ...]>
          #     name: <string>
          #     subtypes: <list or string>
          #     template: <string>
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
        '/pm/config/device/{device}/global/log/custom-format'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'log_customformat': {
            'type': 'dict', 'v_range': [['8.0.0', '']],
            'options': {
                'empty-value-indicator': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'field-exclusion-list': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'log-templates': {
                    'v_range': [['8.0.0', '']],
                    'type': 'list',
                    'options': {
                        'category': {
                            'v_range': [['8.0.0', '']],
                            'choices': [
                                'traffic', 'event', 'virus', 'webfilter', 'attack', 'spam', 'voip', 'dlp', 'app-ctrl', 'anomaly', 'waf', 'gtp', 'dns',
                                'ssh', 'ssl', 'file-filter', 'icap', 'virtual-patch', 'debug'
                            ],
                            'type': 'str'
                        },
                        'name': {'v_range': [['8.0.0', '']], 'type': 'str'},
                        'subtypes': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                        'template': {'v_range': [['8.0.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'name': {'v_range': [['8.0.0', '']], 'required': True, 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'log_customformat'),
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
