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
module: fmgd_router_ospf_area_virtuallink
short_description: OSPF virtual link configuration.
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
  area:
    description: The parameter (area) in requested url.
    type: str
    required: true
  router_ospf_area_virtuallink:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      authentication:
        type: str
        description: Authentication type.
        choices: ['none', 'text', 'md5', 'message-digest']
      authentication_key:
        aliases: ['authentication-key']
        type: list
        elements: str
        description: Authentication key.
      dead_interval:
        aliases: ['dead-interval']
        type: int
        description: Dead interval.
      hello_interval:
        aliases: ['hello-interval']
        type: int
        description: Hello interval.
      keychain:
        type: list
        elements: str
        description: Message-digest key-chain name.
      md5_keys:
        aliases: ['md5-keys']
        type: list
        elements: dict
        description: Md5 keys.
        suboptions:
          id:
            type: int
            description: Key ID
          key_string:
            aliases: ['key-string']
            type: list
            elements: str
            description: Password for the key.
      name:
        type: str
        description: Virtual link entry name.
        required: true
      peer:
        type: str
        description: Peer IP.
      retransmit_interval:
        aliases: ['retransmit-interval']
        type: int
        description: Retransmit interval.
      transmit_delay:
        aliases: ['transmit-delay']
        type: int
        description: Transmit delay.
      md5_keychain:
        aliases: ['md5-keychain']
        type: list
        elements: str
        description: Authentication MD5 key-chain name.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: OSPF virtual link configuration.
      fortinet.fmgdevice.fmgd_router_ospf_area_virtuallink:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        area: <your own value>
        state: present # <value in [present, absent]>
        router_ospf_area_virtuallink:
          name: "your value" # Required variable, string
          # authentication: <value in [none, text, md5, ...]>
          # authentication_key: <list or string>
          # dead_interval: <integer>
          # hello_interval: <integer>
          # keychain: <list or string>
          # md5_keys:
          #   - id: <integer>
          #     key_string: <list or string>
          # peer: <string>
          # retransmit_interval: <integer>
          # transmit_delay: <integer>
          # md5_keychain: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}/virtual-link'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'area': {'required': True, 'type': 'str'},
        'router_ospf_area_virtuallink': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'authentication': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'text', 'md5', 'message-digest'], 'type': 'str'},
                'authentication-key': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'dead-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'hello-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'keychain': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'md5-keys': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'no_log': True,
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'key-string': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'peer': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'retransmit-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'transmit-delay': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'md5-keychain': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_ospf_area_virtuallink'),
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
