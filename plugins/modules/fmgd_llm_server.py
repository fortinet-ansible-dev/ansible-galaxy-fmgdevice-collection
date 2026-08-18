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
module: fmgd_llm_server
short_description: Configure LLM Proxy servers.
version_added: "1.1.0"
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
  llm_server:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      accept_custom_model:
        aliases: ['accept-custom-model']
        type: str
        description: Accept custom model.
        choices: ['disable', 'enable']
      anthropic_version:
        aliases: ['anthropic-version']
        type: str
        description: Anthropic version.
      api_key:
        aliases: ['api-key']
        type: list
        elements: str
        description: Api key.
      azure_api_version:
        aliases: ['azure-api-version']
        type: str
        description: Azure api version.
      azure_resource_name:
        aliases: ['azure-resource-name']
        type: str
        description: Azure resource name.
      built_in_server:
        aliases: ['built-in-server']
        type: str
        description: Built in server.
        choices: ['openai', 'azure', 'azure-openai', 'gemini', 'anthropic', 'grok',
                  'gemini-with-openai-api', 'anthropic-with-openai-api']
      chat_completions_api:
        aliases: ['chat-completions-api']
        type: str
        description: Chat completions api.
        choices: ['none', 'openai', 'azure-openai', 'gemini', 'anthropic']
      custom_model_allow_regex:
        aliases: ['custom-model-allow-regex']
        type: str
        description: Custom model allow regex.
      custom_model_block_regex:
        aliases: ['custom-model-block-regex']
        type: str
        description: Custom model block regex.
      display_name:
        aliases: ['display-name']
        type: str
        description: Display name.
      end_point:
        aliases: ['end-point']
        type: str
        description: End point.
      image_gen_api:
        aliases: ['image-gen-api']
        type: str
        description: Image gen api.
        choices: ['none', 'openai', 'azure-openai']
      models:
        type: list
        elements: str
        description: Models.
      name:
        type: str
        description: Name.
        required: true
      type:
        type: str
        description: Type.
        choices: ['built-in', 'customized']
      verify_cert:
        aliases: ['verify-cert']
        type: str
        description: Verify cert.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure LLM Proxy servers.
      fortinet.fmgdevice.fmgd_llm_server:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        llm_server:
          name: "your value" # Required variable, string
          # accept_custom_model: <value in [disable, enable]>
          # anthropic_version: <string>
          # api_key: <list or string>
          # azure_api_version: <string>
          # azure_resource_name: <string>
          # built_in_server: <value in [openai, azure, azure-openai, ...]>
          # chat_completions_api: <value in [none, openai, azure-openai, ...]>
          # custom_model_allow_regex: <string>
          # custom_model_block_regex: <string>
          # display_name: <string>
          # end_point: <string>
          # image_gen_api: <value in [none, openai, azure-openai]>
          # models: <list or string>
          # type: <value in [built-in, customized]>
          # verify_cert: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/llm/server'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'llm_server': {
            'type': 'dict', 'v_range': [['7.6.5', '']],
            'options': {
                'accept-custom-model': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'anthropic-version': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'api-key': {'v_range': [['7.6.5', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'azure-api-version': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'azure-resource-name': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'built-in-server': {
                    'v_range': [['7.6.5', '']],
                    'choices': ['openai', 'azure', 'azure-openai', 'gemini', 'anthropic', 'grok', 'gemini-with-openai-api', 'anthropic-with-openai-api'],
                    'type': 'str'
                },
                'chat-completions-api': {'v_range': [['7.6.5', '']], 'choices': ['none', 'openai', 'azure-openai', 'gemini', 'anthropic'], 'type': 'str'},
                'custom-model-allow-regex': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'custom-model-block-regex': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'display-name': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'end-point': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'image-gen-api': {'v_range': [['7.6.5', '']], 'choices': ['none', 'openai', 'azure-openai'], 'type': 'str'},
                'models': {'v_range': [['7.6.5', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.6.5', '']], 'required': True, 'type': 'str'},
                'type': {'v_range': [['7.6.5', '']], 'choices': ['built-in', 'customized'], 'type': 'str'},
                'verify-cert': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'llm_server'),
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
