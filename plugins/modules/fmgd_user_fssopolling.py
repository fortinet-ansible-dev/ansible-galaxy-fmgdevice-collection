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
module: fmgd_user_fssopolling
short_description: Configure FSSO active directory servers for polling mode.
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
  user_fssopolling:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      _gui_meta:
        type: str
        description: Gui meta.
      adgrp:
        type: list
        elements: dict
        description: Adgrp.
        suboptions:
          name:
            type: str
            description: Name.
      default_domain:
        aliases: ['default-domain']
        type: str
        description: Default domain managed by this Active Directory server.
      id:
        type: int
        description: Active Directory server ID.
        required: true
      ldap_server:
        aliases: ['ldap-server']
        type: list
        elements: str
        description: LDAP server name used in LDAP connection strings.
      logon_history:
        aliases: ['logon-history']
        type: int
        description: Number of hours of logon history to keep, 0 means keep all history.
      password:
        type: list
        elements: str
        description: Password required to log into this Active Directory server.
      polling_frequency:
        aliases: ['polling-frequency']
        type: int
        description: Polling frequency
      port:
        type: int
        description: Port to communicate with this Active Directory server.
      server:
        type: str
        description: Host name or IP address of the Active Directory server.
      smb_ntlmv1_auth:
        aliases: ['smb-ntlmv1-auth']
        type: str
        description: Enable/disable support of NTLMv1 for Samba authentication.
        choices: ['disable', 'enable']
      smbv1:
        type: str
        description: Enable/disable support of SMBv1 for Samba.
        choices: ['disable', 'enable']
      status:
        type: str
        description: Enable/disable polling for the status of this Active Directory server.
        choices: ['disable', 'enable']
      user:
        type: str
        description: User name required to log into this Active Directory server.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure FSSO active directory servers for polling mode.
      fortinet.fmgdevice.fmgd_user_fssopolling:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        user_fssopolling:
          id: 0 # Required variable, integer
          # _gui_meta: <string>
          # adgrp:
          #   - name: <string>
          # default_domain: <string>
          # ldap_server: <list or string>
          # logon_history: <integer>
          # password: <list or string>
          # polling_frequency: <integer>
          # port: <integer>
          # server: <string>
          # smb_ntlmv1_auth: <value in [disable, enable]>
          # smbv1: <value in [disable, enable]>
          # status: <value in [disable, enable]>
          # user: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/user/fsso-polling'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'user_fssopolling': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                '_gui_meta': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'adgrp': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'default-domain': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'ldap-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'logon-history': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'password': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'polling-frequency': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'smb-ntlmv1-auth': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'smbv1': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'user': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_fssopolling'),
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
