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
module: fmgd_firewall_profileprotocoloptions_smtp
short_description: Configure SMTP protocol options.
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
  profile-protocol-options:
    description: Deprecated, please use "profile_protocol_options"
    type: str
  profile_protocol_options:
    description: The parameter (profile-protocol-options) in requested url.
    type: str
  firewall_profileprotocoloptions_smtp:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      options:
        type: list
        elements: str
        description: One or more options that can be applied to the session.
        choices: ['oversize', 'fragmail', 'splice']
      oversize_limit:
        aliases: ['oversize-limit']
        type: int
        description: Maximum in-memory file size that can be scanned
      ports:
        type: list
        elements: int
        description: Ports to scan for content
      scan_bzip2:
        aliases: ['scan-bzip2']
        type: str
        description: Enable/disable scanning of BZip2 compressed files.
        choices: ['disable', 'enable']
      server_busy:
        aliases: ['server-busy']
        type: str
        description: Enable/disable SMTP server busy when server not available.
        choices: ['disable', 'enable']
      ssl_offloaded:
        aliases: ['ssl-offloaded']
        type: str
        description: SSL decryption and encryption performed by an external device.
        choices: ['no', 'yes']
      status:
        type: str
        description: Enable/disable the active status of scanning for this protocol.
        choices: ['disable', 'enable']
      uncompressed_nest_limit:
        aliases: ['uncompressed-nest-limit']
        type: int
        description: Maximum nested levels of compression that can be uncompressed and scanned
      uncompressed_oversize_limit:
        aliases: ['uncompressed-oversize-limit']
        type: int
        description: Maximum in-memory uncompressed file size that can be scanned
      proxy_after_tcp_handshake:
        aliases: ['proxy-after-tcp-handshake']
        type: str
        description: Proxy traffic after the TCP 3-way handshake has been established
        choices: ['disable', 'enable']
      inspect_all:
        aliases: ['inspect-all']
        type: str
        description: Enable/disable the inspection of all ports for the protocol.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure SMTP protocol options.
      fortinet.fmgdevice.fmgd_firewall_profileprotocoloptions_smtp:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        profile_protocol_options: <your own value>
        firewall_profileprotocoloptions_smtp:
          # options: ["oversize", "fragmail", "splice"]
          # oversize_limit: <integer>
          # ports: <list or integer>
          # scan_bzip2: <value in [disable, enable]>
          # server_busy: <value in [disable, enable]>
          # ssl_offloaded: <value in [no, yes]>
          # status: <value in [disable, enable]>
          # uncompressed_nest_limit: <integer>
          # uncompressed_oversize_limit: <integer>
          # proxy_after_tcp_handshake: <value in [disable, enable]>
          # inspect_all: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/profile-protocol-options/{profile-protocol-options}/smtp'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'profile-protocol-options': {'type': 'str', 'api_name': 'profile_protocol_options'},
        'profile_protocol_options': {'type': 'str'},
        'firewall_profileprotocoloptions_smtp': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'options': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': ['oversize', 'fragmail', 'splice'],
                    'elements': 'str'
                },
                'oversize-limit': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'ports': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                'scan-bzip2': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'server-busy': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-offloaded': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uncompressed-nest-limit': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'uncompressed-oversize-limit': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'proxy-after-tcp-handshake': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'inspect-all': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_profileprotocoloptions_smtp'),
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
