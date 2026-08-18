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
module: fmgd_user_peer
short_description: Configure peer users.
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
  user_peer:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      ca:
        type: list
        elements: str
        description: Name of the CA certificate.
      cn:
        type: str
        description: Peer certificate common name.
      cn_type:
        aliases: ['cn-type']
        type: str
        description: Peer certificate common name type.
        choices: ['string', 'email', 'FQDN', 'ipv4', 'ipv6']
      ldap_mode:
        aliases: ['ldap-mode']
        type: str
        description: Mode for LDAP peer authentication.
        choices: ['password', 'principal-name']
      ldap_password:
        aliases: ['ldap-password']
        type: list
        elements: str
        description: Password for LDAP server bind.
      ldap_server:
        aliases: ['ldap-server']
        type: list
        elements: str
        description: Name of an LDAP server defined under the user ldap command.
      ldap_username:
        aliases: ['ldap-username']
        type: str
        description: Username for LDAP server bind.
      mandatory_ca_verify:
        aliases: ['mandatory-ca-verify']
        type: str
        description: Determine what happens to the peer if the CA certificate is not installed.
        choices: ['disable', 'enable']
      name:
        type: str
        description: Peer name.
        required: true
      ocsp_override_server:
        aliases: ['ocsp-override-server']
        type: list
        elements: str
        description: Online Certificate Status Protocol
      passwd:
        type: list
        elements: str
        description: Peers password used for two-factor authentication.
      subject:
        type: str
        description: Peer certificate name constraints.
      two_factor:
        aliases: ['two-factor']
        type: str
        description: Enable/disable two-factor authentication, applying certificate and password-based authentication.
        choices: ['disable', 'enable']
      mfa_mode:
        aliases: ['mfa-mode']
        type: str
        description: MFA mode for remote peer authentication/authorization.
        choices: ['none', 'password', 'subject-identity']
      mfa_server:
        aliases: ['mfa-server']
        type: list
        elements: str
        description: Name of a remote authenticator.
      mfa_password:
        aliases: ['mfa-password']
        type: list
        elements: str
        description: Unified password for remote authentication.
      mfa_username:
        aliases: ['mfa-username']
        type: str
        description: Unified username for remote authentication.
      checkemail:
        type: str
        description: Peer certificate email address.
      checkhost:
        type: str
        description: Peer certificate hostname.
      checkip:
        type: str
        description: Peer certificate IP address.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure peer users.
      fortinet.fmgdevice.fmgd_user_peer:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        user_peer:
          name: "your value" # Required variable, string
          # ca: <list or string>
          # cn: <string>
          # cn_type: <value in [string, email, FQDN, ...]>
          # ldap_mode: <value in [password, principal-name]>
          # ldap_password: <list or string>
          # ldap_server: <list or string>
          # ldap_username: <string>
          # mandatory_ca_verify: <value in [disable, enable]>
          # ocsp_override_server: <list or string>
          # passwd: <list or string>
          # subject: <string>
          # two_factor: <value in [disable, enable]>
          # mfa_mode: <value in [none, password, subject-identity]>
          # mfa_server: <list or string>
          # mfa_password: <list or string>
          # mfa_username: <string>
          # checkemail: <string>
          # checkhost: <string>
          # checkip: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/user/peer'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'user_peer': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'ca': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'cn': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'cn-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['string', 'email', 'FQDN', 'ipv4', 'ipv6'], 'type': 'str'},
                'ldap-mode': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['password', 'principal-name'], 'type': 'str'},
                'ldap-password': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'ldap-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ldap-username': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'mandatory-ca-verify': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'ocsp-override-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'passwd': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'subject': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'two-factor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mfa-mode': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'password', 'subject-identity'], 'type': 'str'},
                'mfa-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'mfa-password': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'mfa-username': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'checkemail': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'checkhost': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'checkip': {'v_range': [['8.0.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_peer'),
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
