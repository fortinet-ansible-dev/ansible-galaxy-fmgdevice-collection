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
module: fmgd_firewall_accessproxysshclientcert_certextension
short_description: Configure certificate extension for user certificate.
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
  access-proxy-ssh-client-cert:
    description: Deprecated, please use "access_proxy_ssh_client_cert"
    type: str
  access_proxy_ssh_client_cert:
    description: The parameter (access-proxy-ssh-client-cert) in requested url.
    type: str
  firewall_accessproxysshclientcert_certextension:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      critical:
        type: str
        description: Critical option.
        choices: ['no', 'yes']
      data:
        type: str
        description: Data of certificate extension.
      name:
        type: str
        description: Name of certificate extension.
        required: true
      type:
        type: str
        description: Type of certificate extension.
        choices: ['fixed', 'user']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure certificate extension for user certificate.
      fortinet.fmgdevice.fmgd_firewall_accessproxysshclientcert_certextension:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        access_proxy_ssh_client_cert: <your own value>
        state: present # <value in [present, absent]>
        firewall_accessproxysshclientcert_certextension:
          name: "your value" # Required variable, string
          # critical: <value in [no, yes]>
          # data: <string>
          # type: <value in [fixed, user]>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}/cert-extension'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'access-proxy-ssh-client-cert': {'type': 'str', 'api_name': 'access_proxy_ssh_client_cert'},
        'access_proxy_ssh_client_cert': {'type': 'str'},
        'firewall_accessproxysshclientcert_certextension': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'critical': {'v_range': [['7.2.6', '7.2.12'], ['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                'data': {'v_range': [['7.2.6', '7.2.12'], ['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['fixed', 'user'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_accessproxysshclientcert_certextension'),
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
