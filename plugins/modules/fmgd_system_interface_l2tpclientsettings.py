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
module: fmgd_system_interface_l2tpclientsettings
short_description: L2TP client settings.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  interface:
    description: The parameter (interface) in requested url.
    type: str
    required: true
  system_interface_l2tpclientsettings:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      auth_type:
        aliases: ['auth-type']
        type: str
        description: L2TP authentication type.
        choices: ['auto', 'pap', 'chap', 'mschapv1', 'mschapv2']
      defaultgw:
        type: str
        description: Enable/disable default gateway.
        choices: ['disable', 'enable']
      distance:
        type: int
        description: Distance of learned routes.
      hello_interval:
        aliases: ['hello-interval']
        type: int
        description: L2TP hello message interval in seconds
      ip:
        type: list
        elements: str
        description: Ip.
      mtu:
        type: int
        description: L2TP MTU.
      password:
        type: list
        elements: str
        description: L2TP password.
      peer_host:
        aliases: ['peer-host']
        type: str
        description: L2TP peer host address.
      peer_mask:
        aliases: ['peer-mask']
        type: str
        description: L2TP peer mask.
      peer_port:
        aliases: ['peer-port']
        type: int
        description: L2TP peer port number.
      priority:
        type: int
        description: Priority of learned routes.
      user:
        type: str
        description: L2TP user name.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: L2TP client settings.
      fortinet.fmgdevice.fmgd_system_interface_l2tpclientsettings:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        interface: <your own value>
        system_interface_l2tpclientsettings:
          # auth_type: <value in [auto, pap, chap, ...]>
          # defaultgw: <value in [disable, enable]>
          # distance: <integer>
          # hello_interval: <integer>
          # ip: <list or string>
          # mtu: <integer>
          # password: <list or string>
          # peer_host: <string>
          # peer_mask: <string>
          # peer_port: <integer>
          # priority: <integer>
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
        '/pm/config/device/{device}/global/system/interface/{interface}/l2tp-client-settings'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'interface': {'required': True, 'type': 'str'},
        'system_interface_l2tpclientsettings': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'auth-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['auto', 'pap', 'chap', 'mschapv1', 'mschapv2'], 'type': 'str'},
                'defaultgw': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'distance': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'hello-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'mtu': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'password': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'peer-host': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'peer-mask': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'peer-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'user': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_interface_l2tpclientsettings'),
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
