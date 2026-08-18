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
module: fmgd_system_vnetunnel
short_description: Configure virtual network enabler tunnel.
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
  system_vnetunnel:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      auto_asic_offload:
        aliases: ['auto-asic-offload']
        type: str
        description: Enable/disable tunnel ASIC offloading.
        choices: ['disable', 'enable']
      bmr_hostname:
        aliases: ['bmr-hostname']
        type: list
        elements: str
        description: BMR hostname.
      br:
        type: str
        description: IPv6 address or FQDN of the border relay.
      http_password:
        aliases: ['http-password']
        type: list
        elements: str
        description: HTTP authentication password.
      http_username:
        aliases: ['http-username']
        type: str
        description: HTTP authentication user name.
      interface:
        type: list
        elements: str
        description: Interface name.
      ipv4_address:
        aliases: ['ipv4-address']
        type: list
        elements: str
        description: Tunnel IPv4 address and netmask.
      mode:
        type: str
        description: VNE tunnel mode.
        choices: ['map-e', 'fixed-ip', 'ds-lite']
      ssl_certificate:
        aliases: ['ssl-certificate']
        type: list
        elements: str
        description: Name of local certificate for SSL connections.
      status:
        type: str
        description: Enable/disable VNE tunnel.
        choices: ['disable', 'enable']
      update_url:
        aliases: ['update-url']
        type: str
        description: URL of provisioning server.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure virtual network enabler tunnel.
      fortinet.fmgdevice.fmgd_system_vnetunnel:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        system_vnetunnel:
          # auto_asic_offload: <value in [disable, enable]>
          # bmr_hostname: <list or string>
          # br: <string>
          # http_password: <list or string>
          # http_username: <string>
          # interface: <list or string>
          # ipv4_address: <list or string>
          # mode: <value in [map-e, fixed-ip, ds-lite]>
          # ssl_certificate: <list or string>
          # status: <value in [disable, enable]>
          # update_url: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/vne-tunnel'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_vnetunnel': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'auto-asic-offload': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bmr-hostname': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'br': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'http-password': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'http-username': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ipv4-address': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['map-e', 'fixed-ip', 'ds-lite'], 'type': 'str'},
                'ssl-certificate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_vnetunnel'),
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
