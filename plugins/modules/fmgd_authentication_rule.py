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
module: fmgd_authentication_rule
short_description: Configure Authentication Rules.
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
  authentication_rule:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      active_auth_method:
        aliases: ['active-auth-method']
        type: list
        elements: str
        description: Select an active authentication method.
      comments:
        type: str
        description: Comment.
      cors_depth:
        aliases: ['cors-depth']
        type: int
        description: Depth to allow CORS access
      cors_stateful:
        aliases: ['cors-stateful']
        type: str
        description: Enable/disable allowance of CORS access
        choices: ['disable', 'enable']
      dstaddr:
        type: list
        elements: str
        description: Select an IPv4 destination address from available options.
      dstaddr6:
        type: list
        elements: str
        description: Select an IPv6 destination address from available options.
      form_auth_fallback:
        aliases: ['form-auth-fallback']
        type: str
        description: Form auth fallback.
        choices: ['disable', 'enable']
      ip_based:
        aliases: ['ip-based']
        type: str
        description: Enable/disable IP-based authentication.
        choices: ['disable', 'enable']
      name:
        type: str
        description: Authentication rule name.
        required: true
      protocol:
        type: str
        description: Authentication is required for the selected protocol
        choices: ['http', 'ftp', 'socks', 'ssh', 'ztna-portal']
      srcaddr:
        type: list
        elements: str
        description: Authentication is required for the selected IPv4 source address.
      srcaddr6:
        type: list
        elements: str
        description: Authentication is required for the selected IPv6 source address.
      srcintf:
        type: list
        elements: str
        description: Incoming
      sso_auth_method:
        aliases: ['sso-auth-method']
        type: list
        elements: str
        description: Select a single-sign on
      status:
        type: str
        description: Enable/disable this authentication rule.
        choices: ['disable', 'enable']
      transaction_based:
        aliases: ['transaction-based']
        type: str
        description: Enable/disable transaction based authentication
        choices: ['disable', 'enable']
      web_auth_cookie:
        aliases: ['web-auth-cookie']
        type: str
        description: Enable/disable Web authentication cookies
        choices: ['disable', 'enable']
      web_portal:
        aliases: ['web-portal']
        type: str
        description: Enable/disable web portal for proxy transparent policy
        choices: ['disable', 'enable']
      web_proxy:
        aliases: ['web-proxy']
        type: list
        elements: str
        description: Web proxy.
      cert_auth_cookie:
        aliases: ['cert-auth-cookie']
        type: str
        description: Enable/disable to use device certificate as authentication cookie
        choices: ['disable', 'enable']
      session_logout:
        aliases: ['session-logout']
        type: str
        description: Enable/disable logout of a user from the current session.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure Authentication Rules.
      fortinet.fmgdevice.fmgd_authentication_rule:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        authentication_rule:
          name: "your value" # Required variable, string
          # active_auth_method: <list or string>
          # comments: <string>
          # cors_depth: <integer>
          # cors_stateful: <value in [disable, enable]>
          # dstaddr: <list or string>
          # dstaddr6: <list or string>
          # form_auth_fallback: <value in [disable, enable]>
          # ip_based: <value in [disable, enable]>
          # protocol: <value in [http, ftp, socks, ...]>
          # srcaddr: <list or string>
          # srcaddr6: <list or string>
          # srcintf: <list or string>
          # sso_auth_method: <list or string>
          # status: <value in [disable, enable]>
          # transaction_based: <value in [disable, enable]>
          # web_auth_cookie: <value in [disable, enable]>
          # web_portal: <value in [disable, enable]>
          # web_proxy: <list or string>
          # cert_auth_cookie: <value in [disable, enable]>
          # session_logout: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/authentication/rule'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'authentication_rule': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'active-auth-method': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'comments': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'cors-depth': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'cors-stateful': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dstaddr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dstaddr6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'form-auth-fallback': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip-based': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'protocol': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['http', 'ftp', 'socks', 'ssh', 'ztna-portal'], 'type': 'str'},
                'srcaddr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'srcaddr6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'srcintf': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'sso-auth-method': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'transaction-based': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'web-auth-cookie': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'web-portal': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'web-proxy': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'cert-auth-cookie': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'session-logout': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'authentication_rule'),
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
