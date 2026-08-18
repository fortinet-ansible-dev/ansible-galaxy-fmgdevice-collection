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
module: fmgd_llm_profile
short_description: Configure LLM Proxy profiles.
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
  llm_profile:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      chat:
        type: dict
        description: Chat.
        suboptions:
          max_completion_tokens:
            aliases: ['max-completion-tokens']
            type: int
            description: Max completion tokens.
          max_req_len:
            aliases: ['max-req-len']
            type: int
            description: Max req len.
          status:
            type: str
            description: Status.
            choices: ['disable', 'enable']
          stream:
            type: str
            description: Stream.
            choices: ['block', 'bypass']
          system_prompt:
            aliases: ['system-prompt']
            type: str
            description: System prompt.
          system_prompt_mode:
            aliases: ['system-prompt-mode']
            type: str
            description: System prompt mode.
            choices: ['bypass', 'replace', 'prepend', 'append']
      image_gen:
        aliases: ['image-gen']
        type: dict
        description: Image gen.
        suboptions:
          status:
            type: str
            description: Status.
            choices: ['disable', 'enable']
      list_models:
        aliases: ['list-models']
        type: dict
        description: List models.
        suboptions:
          status:
            type: str
            description: Status.
            choices: ['disable', 'enable']
      log:
        type: str
        description: Log.
        choices: ['none', 'all', 'blocked']
      name:
        type: str
        description: Name.
        required: true
      response:
        type: dict
        description: Response.
        suboptions:
          instructions:
            type: str
            description: Instructions.
          instructions_mode:
            aliases: ['instructions-mode']
            type: str
            description: Instructions mode.
            choices: ['bypass', 'replace', 'prepend', 'append']
          max_output_tokens:
            aliases: ['max-output-tokens']
            type: int
            description: Max output tokens.
          max_req_len:
            aliases: ['max-req-len']
            type: int
            description: Max req len.
          status:
            type: str
            description: Status.
            choices: ['disable', 'enable']
          stream:
            type: str
            description: Stream.
            choices: ['block', 'bypass']
      unknown_api:
        aliases: ['unknown-api']
        type: str
        description: Unknown api.
        choices: ['disable', 'enable']
      replace_api_key:
        aliases: ['replace-api-key']
        type: str
        description: Replace api key.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure LLM Proxy profiles.
      fortinet.fmgdevice.fmgd_llm_profile:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        llm_profile:
          name: "your value" # Required variable, string
          # chat:
          #   max_completion_tokens: <integer>
          #   max_req_len: <integer>
          #   status: <value in [disable, enable]>
          #   stream: <value in [block, bypass]>
          #   system_prompt: <string>
          #   system_prompt_mode: <value in [bypass, replace, prepend, ...]>
          # image_gen:
          #   status: <value in [disable, enable]>
          # list_models:
          #   status: <value in [disable, enable]>
          # log: <value in [none, all, blocked]>
          # response:
          #   instructions: <string>
          #   instructions_mode: <value in [bypass, replace, prepend, ...]>
          #   max_output_tokens: <integer>
          #   max_req_len: <integer>
          #   status: <value in [disable, enable]>
          #   stream: <value in [block, bypass]>
          # unknown_api: <value in [disable, enable]>
          # replace_api_key: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/llm/profile'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'llm_profile': {
            'type': 'dict', 'v_range': [['7.6.5', '']],
            'options': {
                'chat': {
                    'v_range': [['7.6.5', '']],
                    'type': 'dict',
                    'options': {
                        'max-completion-tokens': {'v_range': [['7.6.5', '']], 'no_log': True, 'type': 'int'},
                        'max-req-len': {'v_range': [['7.6.5', '']], 'type': 'int'},
                        'status': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'stream': {'v_range': [['7.6.5', '']], 'choices': ['block', 'bypass'], 'type': 'str'},
                        'system-prompt': {'v_range': [['7.6.5', '']], 'type': 'str'},
                        'system-prompt-mode': {'v_range': [['7.6.5', '']], 'choices': ['bypass', 'replace', 'prepend', 'append'], 'type': 'str'}
                    }
                },
                'image-gen': {
                    'v_range': [['7.6.5', '']],
                    'type': 'dict',
                    'options': {'status': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}}
                },
                'list-models': {
                    'v_range': [['7.6.5', '']],
                    'type': 'dict',
                    'options': {'status': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}}
                },
                'log': {'v_range': [['7.6.5', '']], 'choices': ['none', 'all', 'blocked'], 'type': 'str'},
                'name': {'v_range': [['7.6.5', '']], 'required': True, 'type': 'str'},
                'response': {
                    'v_range': [['7.6.5', '']],
                    'type': 'dict',
                    'options': {
                        'instructions': {'v_range': [['7.6.5', '']], 'type': 'str'},
                        'instructions-mode': {'v_range': [['7.6.5', '']], 'choices': ['bypass', 'replace', 'prepend', 'append'], 'type': 'str'},
                        'max-output-tokens': {'v_range': [['7.6.5', '']], 'no_log': True, 'type': 'int'},
                        'max-req-len': {'v_range': [['7.6.5', '']], 'type': 'int'},
                        'status': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'stream': {'v_range': [['7.6.5', '']], 'choices': ['block', 'bypass'], 'type': 'str'}
                    }
                },
                'unknown-api': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'replace-api-key': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'llm_profile'),
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
