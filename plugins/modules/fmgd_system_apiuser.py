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
module: fmgd_system_apiuser
short_description: Configure API users.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_apiuser:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      accprofile:
        type: list
        elements: str
        description: Admin user access profile.
      api_key:
        aliases: ['api-key']
        type: list
        elements: str
        description: Admin user password.
      comments:
        type: str
        description: Comment.
      cors_allow_origin:
        aliases: ['cors-allow-origin']
        type: str
        description: Value for Access-Control-Allow-Origin on API responses.
      name:
        type: str
        description: User name.
        required: true
      peer_auth:
        aliases: ['peer-auth']
        type: str
        description: Enable/disable peer authentication.
        choices: ['disable', 'enable']
      peer_group:
        aliases: ['peer-group']
        type: list
        elements: str
        description: Peer group name.
      schedule:
        type: str
        description: Schedule name.
      trusthost:
        type: list
        elements: dict
        description: Trusthost.
        suboptions:
          id:
            type: int
            description: ID.
          ipv4_trusthost:
            aliases: ['ipv4-trusthost']
            type: list
            elements: str
            description: IPv4 trusted host address.
          ipv6_trusthost:
            aliases: ['ipv6-trusthost']
            type: str
            description: IPv6 trusted host address.
          type:
            type: str
            description: Trusthost type.
            choices: ['ipv4-trusthost', 'ipv6-trusthost']
      vdom:
        type: list
        elements: str
        description: Virtual domains.
      expire-at:
        type: int
        description: Deprecated, please rename it to expire_at. Expiry of this API key in Unix Epoch time.
      expire_at:
        type: int
        description: Expire at.
      old_password:
        aliases: ['old-password']
        type: list
        elements: str
        description: Old password.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure API users.
      fortinet.fmgdevice.fmgd_system_apiuser:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        system_apiuser:
          name: "your value" # Required variable, string
          # accprofile: <list or string>
          # api_key: <list or string>
          # comments: <string>
          # cors_allow_origin: <string>
          # peer_auth: <value in [disable, enable]>
          # peer_group: <list or string>
          # schedule: <string>
          # trusthost:
          #   - id: <integer>
          #     ipv4_trusthost: <list or string>
          #     ipv6_trusthost: <string>
          #     type: <value in [ipv4-trusthost, ipv6-trusthost]>
          # vdom: <list or string>
          # expire_at: <integer>
          # expire_at: <integer>
          # old_password: <list or string>
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
        '/pm/config/device/{device}/global/system/api-user'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_apiuser': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'accprofile': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'api-key': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'comments': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'cors-allow-origin': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'peer-auth': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'peer-group': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'schedule': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'trusthost': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'ipv4-trusthost': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'ipv6-trusthost': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['ipv4-trusthost', 'ipv6-trusthost'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'vdom': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'expire-at': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'expire_at': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'old-password': {'v_range': [['7.6.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_apiuser'),
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
