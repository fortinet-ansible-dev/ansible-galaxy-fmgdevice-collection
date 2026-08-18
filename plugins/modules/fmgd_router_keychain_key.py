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
module: fmgd_router_keychain_key
short_description: Configuration method to edit key settings.
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
  key-chain:
    description: Deprecated, please use "key_chain"
    type: str
  key_chain:
    description: The parameter (key-chain) in requested url.
    type: str
  router_keychain_key:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      accept_lifetime:
        aliases: ['accept-lifetime']
        type: str
        description: Lifetime of received authentication key
      algorithm:
        type: str
        description: Cryptographic algorithm.
        choices: ['md5', 'hmac-sha1', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512', 'cmac-aes128']
      id:
        type: str
        description: Key ID
        required: true
      key_string:
        aliases: ['key-string']
        type: list
        elements: str
        description: Password for the key
      send_lifetime:
        aliases: ['send-lifetime']
        type: str
        description: Lifetime of sent authentication key
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configuration method to edit key settings.
      fortinet.fmgdevice.fmgd_router_keychain_key:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        key_chain: <your own value>
        state: present # <value in [present, absent]>
        router_keychain_key:
          id: "your value" # Required variable, string
          # accept_lifetime: <string>
          # algorithm: <value in [md5, hmac-sha1, hmac-sha256, ...]>
          # key_string: <list or string>
          # send_lifetime: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/key-chain/{key-chain}/key'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'key-chain': {'type': 'str', 'no_log': False, 'api_name': 'key_chain'},
        'key_chain': {'type': 'str', 'no_log': False},
        'router_keychain_key': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': False,
            'options': {
                'accept-lifetime': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'algorithm': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['md5', 'hmac-sha1', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512', 'cmac-aes128'],
                    'type': 'str'
                },
                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'key-string': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'send-lifetime': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_keychain_key'),
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
