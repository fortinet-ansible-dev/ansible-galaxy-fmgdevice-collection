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
module: fmgd_system_ssoforticloudadmin
short_description: Configure FortiCloud SSO admin users.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_ssoforticloudadmin:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      accprofile:
        type: list
        elements: str
        description: FortiCloud SSO admin user access profile.
      gui_default_dashboard_template:
        aliases: ['gui-default-dashboard-template']
        type: str
        description: The default dashboard template.
      gui_ignore_invalid_signature_version:
        aliases: ['gui-ignore-invalid-signature-version']
        type: str
        description: FortiOS image build version to ignore invalid signature warning for.
      gui_ignore_release_overview_version:
        aliases: ['gui-ignore-release-overview-version']
        type: str
        description: FortiOS version to ignore release overview prompt for.
      name:
        type: str
        description: FortiCloud SSO admin name.
        required: true
      vdom:
        type: list
        elements: str
        description: Virtual domain
      gui_custom_theme:
        aliases: ['gui-custom-theme']
        type: list
        elements: str
        description: Custom theme that overrides the default FortiGate theme.
      gui_dashboard_id:
        aliases: ['gui-dashboard-id']
        type: int
        description: GUI Dashboard ID.
      gui_llm_provider:
        aliases: ['gui-llm-provider']
        type: str
        description: Select the LLM provider.
        choices: ['fortiai', 'openai']
      gui_theme:
        aliases: ['gui-theme']
        type: str
        description: Predefined theme that overrides the default FortiGate theme.
        choices: ['melongene', 'mariner', 'neutrino', 'jade', 'graphite', 'dark-matter', 'onyx',
                  'eclipse', 'retro', 'jet-stream', 'security-fabric', 'none']
      gui_theme_type:
        aliases: ['gui-theme-type']
        type: str
        description: Use predefined themes or custom themes.
        choices: ['predefined', 'custom']
      openai_api_key:
        aliases: ['openai-api-key']
        type: list
        elements: str
        description: OpenAI API key.
      openai_api_key_part2:
        aliases: ['openai-api-key-part2']
        type: list
        elements: str
        description: OpenAI API key part 2 for excess length.
      openai_model:
        aliases: ['openai-model']
        type: str
        description: OpenAI model.
      openai_org_id:
        aliases: ['openai-org-id']
        type: str
        description: OpenAI organization ID.
      openai_project_id:
        aliases: ['openai-project-id']
        type: str
        description: OpenAI project ID.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure FortiCloud SSO admin users.
      fortinet.fmgdevice.fmgd_system_ssoforticloudadmin:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        system_ssoforticloudadmin:
          name: "your value" # Required variable, string
          # accprofile: <list or string>
          # gui_default_dashboard_template: <string>
          # gui_ignore_invalid_signature_version: <string>
          # gui_ignore_release_overview_version: <string>
          # vdom: <list or string>
          # gui_custom_theme: <list or string>
          # gui_dashboard_id: <integer>
          # gui_llm_provider: <value in [fortiai, openai]>
          # gui_theme: <value in [melongene, mariner, neutrino, ...]>
          # gui_theme_type: <value in [predefined, custom]>
          # openai_api_key: <list or string>
          # openai_api_key_part2: <list or string>
          # openai_model: <string>
          # openai_org_id: <string>
          # openai_project_id: <string>
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
        '/pm/config/device/{device}/global/system/sso-forticloud-admin'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_ssoforticloudadmin': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'accprofile': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'gui-default-dashboard-template': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'gui-ignore-invalid-signature-version': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'gui-ignore-release-overview-version': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'vdom': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'gui-custom-theme': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'gui-dashboard-id': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'gui-llm-provider': {'v_range': [['8.0.0', '']], 'choices': ['fortiai', 'openai'], 'type': 'str'},
                'gui-theme': {
                    'v_range': [['8.0.0', '']],
                    'choices': [
                        'melongene', 'mariner', 'neutrino', 'jade', 'graphite', 'dark-matter', 'onyx', 'eclipse', 'retro', 'jet-stream',
                        'security-fabric', 'none'
                    ],
                    'type': 'str'
                },
                'gui-theme-type': {'v_range': [['8.0.0', '']], 'choices': ['predefined', 'custom'], 'type': 'str'},
                'openai-api-key': {'v_range': [['8.0.0', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'openai-api-key-part2': {'v_range': [['8.0.0', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'openai-model': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'openai-org-id': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'openai-project-id': {'v_range': [['8.0.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_ssoforticloudadmin'),
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
