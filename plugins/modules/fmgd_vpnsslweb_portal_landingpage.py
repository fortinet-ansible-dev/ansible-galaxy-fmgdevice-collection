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
module: fmgd_vpnsslweb_portal_landingpage
short_description: Landing page options.
version_added: "1.1.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  vdom:
    description: The parameter (vdom) in requested url.
    type: str
    required: true
  portal:
    description: The parameter (portal) in requested url.
    type: str
    required: true
  vpnsslweb_portal_landingpage:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      form_data:
        aliases: ['form-data']
        type: list
        elements: dict
        description: Form data.
        suboptions:
          name:
            type: str
            description: Name.
          value:
            type: str
            description: Value.
      sso:
        type: str
        description: Single sign-on.
        choices: ['disable', 'static', 'auto']
      sso_credential:
        aliases: ['sso-credential']
        type: str
        description: Single sign-on credentials.
        choices: ['sslvpn-login', 'alternative']
      sso_password:
        aliases: ['sso-password']
        type: list
        elements: str
        description: SSO password.
      sso_username:
        aliases: ['sso-username']
        type: str
        description: SSO user name.
      url:
        type: str
        description: Landing page URL.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Landing page options.
      fortinet.fmgdevice.fmgd_vpnsslweb_portal_landingpage:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        portal: <your own value>
        vpnsslweb_portal_landingpage:
          # form_data:
          #   - name: <string>
          #     value: <string>
          # sso: <value in [disable, static, auto]>
          # sso_credential: <value in [sslvpn-login, alternative]>
          # sso_password: <list or string>
          # sso_username: <string>
          # url: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/portal/{portal}/landing-page'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'portal': {'required': True, 'type': 'str'},
        'vpnsslweb_portal_landingpage': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'form-data': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'value': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'sso': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'static', 'auto'], 'type': 'str'},
                'sso-credential': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['sslvpn-login', 'alternative'], 'type': 'str'},
                'sso-password': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'sso-username': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'url': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpnsslweb_portal_landingpage'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
