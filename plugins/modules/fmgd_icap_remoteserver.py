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
module: fmgd_icap_remoteserver
short_description: Device vdom icap remote server
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
  icap_remoteserver:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      addr_type:
        aliases: ['addr-type']
        type: str
        description: Addr type.
        choices: ['fqdn', 'ip4', 'ip6']
      fqdn:
        type: str
        description: Fqdn.
      healthcheck:
        type: str
        description: Healthcheck.
        choices: ['disable', 'enable']
      healthcheck_service:
        aliases: ['healthcheck-service']
        type: str
        description: Healthcheck service.
      ip_address:
        aliases: ['ip-address']
        type: str
        description: IPv4 address of the ICAP server.
      ip6_address:
        aliases: ['ip6-address']
        type: str
        description: IPv6 address of the ICAP server.
      max_connections:
        aliases: ['max-connections']
        type: int
        description: Maximum number of concurrent connections to ICAP server.
      name:
        type: str
        description: Server name.
        required: true
      port:
        type: int
        description: ICAP server port.
      secure:
        type: str
        description: Enable/disable secure connection to icap server.
        choices: ['disable', 'enable']
      ssl_cert:
        aliases: ['ssl-cert']
        type: list
        elements: str
        description: Ssl cert.
      ca_cert:
        aliases: ['ca-cert']
        type: list
        elements: str
        description: CA certificate name.
      ip_version:
        aliases: ['ip-version']
        type: str
        description: IP version.
        choices: ['4', '6']
      secure_port:
        aliases: ['secure-port']
        type: int
        description: ICAP server secure port
      validate_server_certificate:
        aliases: ['validate-server-certificate']
        type: str
        description: Validate server certificate.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Device vdom icap remote server
      fortinet.fmgdevice.fmgd_icap_remoteserver:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        icap_remoteserver:
          name: "your value" # Required variable, string
          # addr_type: <value in [fqdn, ip4, ip6]>
          # fqdn: <string>
          # healthcheck: <value in [disable, enable]>
          # healthcheck_service: <string>
          # ip_address: <string>
          # ip6_address: <string>
          # max_connections: <integer>
          # port: <integer>
          # secure: <value in [disable, enable]>
          # ssl_cert: <list or string>
          # ca_cert: <list or string>
          # ip_version: <value in [4, 6]>
          # secure_port: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/icap/remote-server'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'icap_remoteserver': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'addr-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['fqdn', 'ip4', 'ip6'], 'type': 'str'},
                'fqdn': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'healthcheck': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'healthcheck-service': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'ip-address': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'ip6-address': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'max-connections': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'secure': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-cert': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ca-cert': {'v_range': [['7.4.8', '7.4.11'], ['7.6.5', '']], 'type': 'list', 'elements': 'str'},
                'ip-version': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['4', '6'], 'type': 'str'},
                'secure-port': {'v_range': [['7.4.8', '7.4.11']], 'type': 'int'},
                'validate-server-certificate': {'v_range': [['7.6.4', '7.6.4']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'icap_remoteserver'),
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
