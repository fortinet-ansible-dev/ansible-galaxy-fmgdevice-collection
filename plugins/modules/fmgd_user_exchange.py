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
module: fmgd_user_exchange
short_description: Configure MS Exchange server entries.
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
  user_exchange:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      auth_level:
        aliases: ['auth-level']
        type: str
        description: Authentication security level used for the RPC protocol layer.
        choices: ['connect', 'call', 'packet', 'integrity', 'privacy', 'medium', 'high', 'normal',
                  'low']
      auth_type:
        aliases: ['auth-type']
        type: str
        description: Authentication security type used for the RPC protocol layer.
        choices: ['spnego', 'ntlm', 'kerberos']
      auto_discover_kdc:
        aliases: ['auto-discover-kdc']
        type: str
        description: Enable/disable automatic discovery of KDC IP addresses.
        choices: ['disable', 'enable']
      connect_protocol:
        aliases: ['connect-protocol']
        type: str
        description: Connection protocol used to connect to MS Exchange service.
        choices: ['rpc-over-tcp', 'rpc-over-http', 'rpc-over-https']
      domain_name:
        aliases: ['domain-name']
        type: str
        description: MS Exchange server fully qualified domain name.
      http_auth_type:
        aliases: ['http-auth-type']
        type: str
        description: Authentication security type used for the HTTP transport.
        choices: ['ntlm', 'basic']
      ip:
        type: str
        description: Server IPv4 address.
      kdc_ip:
        aliases: ['kdc-ip']
        type: list
        elements: str
        description: KDC IPv4 addresses for Kerberos authentication.
      name:
        type: str
        description: MS Exchange server entry name.
        required: true
      password:
        type: list
        elements: str
        description: Password for the specified username.
      server_name:
        aliases: ['server-name']
        type: str
        description: MS Exchange server hostname.
      ssl_min_proto_version:
        aliases: ['ssl-min-proto-version']
        type: str
        description: Minimum SSL/TLS protocol version for HTTPS transport
        choices: ['default', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1', 'TLSv1-3']
      username:
        type: str
        description: User name used to sign in to the server.
      validate_server_certificate:
        aliases: ['validate-server-certificate']
        type: str
        description: Enable/disable exchange server certificate validation.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure MS Exchange server entries.
      fortinet.fmgdevice.fmgd_user_exchange:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        user_exchange:
          name: "your value" # Required variable, string
          # auth_level: <value in [connect, call, packet, ...]>
          # auth_type: <value in [spnego, ntlm, kerberos]>
          # auto_discover_kdc: <value in [disable, enable]>
          # connect_protocol: <value in [rpc-over-tcp, rpc-over-http, rpc-over-https]>
          # domain_name: <string>
          # http_auth_type: <value in [ntlm, basic]>
          # ip: <string>
          # kdc_ip: <list or string>
          # password: <list or string>
          # server_name: <string>
          # ssl_min_proto_version: <value in [default, TLSv1-1, TLSv1-2, ...]>
          # username: <string>
          # validate_server_certificate: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/user/exchange'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'user_exchange': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'auth-level': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['connect', 'call', 'packet', 'integrity', 'privacy', 'medium', 'high', 'normal', 'low'],
                    'type': 'str'
                },
                'auth-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['spnego', 'ntlm', 'kerberos'], 'type': 'str'},
                'auto-discover-kdc': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'connect-protocol': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['rpc-over-tcp', 'rpc-over-http', 'rpc-over-https'],
                    'type': 'str'
                },
                'domain-name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'http-auth-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['ntlm', 'basic'], 'type': 'str'},
                'ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'kdc-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'password': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'server-name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'ssl-min-proto-version': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['default', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1', 'TLSv1-3'],
                    'type': 'str'
                },
                'username': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'validate-server-certificate': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_exchange'),
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
