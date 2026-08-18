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
module: fmgd_system_interface_ipv6_vrrp6
short_description: IPv6 VRRP configuration.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  interface:
    description: The parameter (interface) in requested url.
    type: str
    required: true
  system_interface_ipv6_vrrp6:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      accept_mode:
        aliases: ['accept-mode']
        type: str
        description: Enable/disable accept mode.
        choices: ['disable', 'enable']
      adv_interval:
        aliases: ['adv-interval']
        type: int
        description: Advertisement interval
      ignore_default_route:
        aliases: ['ignore-default-route']
        type: str
        description: Enable/disable ignoring of default route when checking destination.
        choices: ['disable', 'enable']
      preempt:
        type: str
        description: Enable/disable preempt mode.
        choices: ['disable', 'enable']
      priority:
        type: int
        description: Priority of the virtual router
      start_time:
        aliases: ['start-time']
        type: int
        description: Startup time
      status:
        type: str
        description: Enable/disable VRRP.
        choices: ['disable', 'enable']
      vrdst6:
        type: list
        elements: str
        description: Monitor the route to this destination.
      vrgrp:
        type: int
        description: VRRP group ID
      vrid:
        type: int
        description: Virtual router identifier
      vrip6:
        type: str
        description: IPv6 address of the virtual router.
      vrdst_priority:
        aliases: ['vrdst-priority']
        type: int
        description: Priority of the virtual router when the virtual router destination becomes unreachable
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: IPv6 VRRP configuration.
      fortinet.fmgdevice.fmgd_system_interface_ipv6_vrrp6:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        interface: <your own value>
        state: present # <value in [present, absent]>
        system_interface_ipv6_vrrp6:
          # accept_mode: <value in [disable, enable]>
          # adv_interval: <integer>
          # ignore_default_route: <value in [disable, enable]>
          # preempt: <value in [disable, enable]>
          # priority: <integer>
          # start_time: <integer>
          # status: <value in [disable, enable]>
          # vrdst6: <list or string>
          # vrgrp: <integer>
          # vrid: <integer>
          # vrip6: <string>
          # vrdst_priority: <integer>
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
        '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/vrrp6'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'interface': {'required': True, 'type': 'str'},
        'system_interface_ipv6_vrrp6': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'accept-mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'adv-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'ignore-default-route': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'preempt': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'start-time': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vrdst6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'vrgrp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'vrid': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'vrip6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'vrdst-priority': {'v_range': [['7.6.0', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_interface_ipv6_vrrp6'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
