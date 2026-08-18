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
module: fmgd_ftpproxy_explicit
short_description: Configure explicit FTP proxy settings.
version_added: "1.0.0"
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
  ftpproxy_explicit:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      incoming_ip:
        aliases: ['incoming-ip']
        type: str
        description: Accept incoming FTP requests from this IP address.
      incoming_port:
        aliases: ['incoming-port']
        type: list
        elements: str
        description: Accept incoming FTP requests on one or more ports.
      outgoing_ip:
        aliases: ['outgoing-ip']
        type: list
        elements: str
        description: Outgoing FTP requests will leave from this IP address.
      sec_default_action:
        aliases: ['sec-default-action']
        type: str
        description: Accept or deny explicit FTP proxy sessions when no FTP proxy firewall policy exists.
        choices: ['deny', 'accept']
      server_data_mode:
        aliases: ['server-data-mode']
        type: str
        description: Determine mode of data session on FTP server side.
        choices: ['client', 'passive']
      ssl:
        type: str
        description: Enable/disable the explicit FTPS proxy.
        choices: ['disable', 'enable']
      ssl_algorithm:
        aliases: ['ssl-algorithm']
        type: str
        description: Relative strength of encryption algorithms accepted in negotiation.
        choices: ['high', 'low', 'medium']
      ssl_cert:
        aliases: ['ssl-cert']
        type: list
        elements: str
        description: List of certificate names to use for SSL connections to this server.
      ssl_dh_bits:
        aliases: ['ssl-dh-bits']
        type: str
        description: Bit-size of Diffie-Hellman
        choices: ['768', '1024', '1536', '2048']
      status:
        type: str
        description: Enable/disable the explicit FTP proxy.
        choices: ['disable', 'enable']
      active_src_port:
        aliases: ['active-src-port']
        type: str
        description: Active src port.
        choices: ['default', 'server']
      incoming_ip6:
        aliases: ['incoming-ip6']
        type: str
        description: Incoming ip6.
      ipv6_status:
        aliases: ['ipv6-status']
        type: str
        description: Ipv6 status.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure explicit FTP proxy settings.
      fortinet.fmgdevice.fmgd_ftpproxy_explicit:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        ftpproxy_explicit:
          # incoming_ip: <string>
          # incoming_port: <list or string>
          # outgoing_ip: <list or string>
          # sec_default_action: <value in [deny, accept]>
          # server_data_mode: <value in [client, passive]>
          # ssl: <value in [disable, enable]>
          # ssl_algorithm: <value in [high, low, medium]>
          # ssl_cert: <list or string>
          # ssl_dh_bits: <value in [768, 1024, 1536, ...]>
          # status: <value in [disable, enable]>
          # active_src_port: <value in [default, server]>
          # incoming_ip6: <string>
          # ipv6_status: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/ftp-proxy/explicit'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'ftpproxy_explicit': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'incoming-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'incoming-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'outgoing-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'sec-default-action': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['deny', 'accept'], 'type': 'str'},
                'server-data-mode': {'v_range': [['7.4.3', '']], 'choices': ['client', 'passive'], 'type': 'str'},
                'ssl': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-algorithm': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['high', 'low', 'medium'], 'type': 'str'},
                'ssl-cert': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ssl-dh-bits': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['768', '1024', '1536', '2048'], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'active-src-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['default', 'server'], 'type': 'str'},
                'incoming-ip6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'ipv6-status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'ftpproxy_explicit'),
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
