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
module: fmgd_system_linkmonitor_serverlist
short_description: Servers for link-monitor to monitor.
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
  link-monitor:
    description: Deprecated, please use "link_monitor"
    type: str
  link_monitor:
    description: The parameter (link-monitor) in requested url.
    type: str
  system_linkmonitor_serverlist:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      dst:
        type: str
        description: IP address of the server to be monitored.
      id:
        type: int
        description: Server ID.
        required: true
      port:
        type: int
        description: Port number of the traffic to be used to monitor the server.
      protocol:
        type: list
        elements: str
        description: Protocols used to monitor the server.
        choices: ['ping', 'tcp-echo', 'udp-echo', 'http', 'twamp', 'https']
      weight:
        type: int
        description: Weight of the monitor to this dst
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Servers for link-monitor to monitor.
      fortinet.fmgdevice.fmgd_system_linkmonitor_serverlist:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        link_monitor: <your own value>
        state: present # <value in [present, absent]>
        system_linkmonitor_serverlist:
          id: 0 # Required variable, integer
          # dst: <string>
          # port: <integer>
          # protocol: ["ping", "tcp-echo", "udp-echo", "http", "twamp", "https"]
          # weight: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/link-monitor/{link-monitor}/server-list'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'link-monitor': {'type': 'str', 'api_name': 'link_monitor'},
        'link_monitor': {'type': 'str'},
        'system_linkmonitor_serverlist': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'dst': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'protocol': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['ping', 'tcp-echo', 'udp-echo', 'http', 'twamp', 'https'],
                    'elements': 'str'
                },
                'weight': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_linkmonitor_serverlist'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
