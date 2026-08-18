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
module: fmgd_wanopt_cacheservice
short_description: Designate cache-service for wan-optimization and webcache.
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
  wanopt_cacheservice:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      acceptable_connections:
        aliases: ['acceptable-connections']
        type: str
        description: Set strategy when accepting cache collaboration connection.
        choices: ['any', 'peers']
      collaboration:
        type: str
        description: Enable/disable cache-collaboration between cache-service clusters.
        choices: ['disable', 'enable']
      device_id:
        aliases: ['device-id']
        type: str
        description: Set identifier for this cache device.
      dst_peer:
        aliases: ['dst-peer']
        type: list
        elements: dict
        description: Dst peer.
        suboptions:
          auth_type:
            aliases: ['auth-type']
            type: int
            description: Set authentication type for this peer.
          device_id:
            aliases: ['device-id']
            type: str
            description: Device ID of this peer.
          encode_type:
            aliases: ['encode-type']
            type: int
            description: Set encode type for this peer.
          ip:
            type: str
            description: Set cluster IP address of this peer.
          priority:
            type: int
            description: Set priority for this peer.
      prefer_scenario:
        aliases: ['prefer-scenario']
        type: str
        description: Set the preferred cache behavior towards the balance between latency and hit-ratio.
        choices: ['balance', 'prefer-speed', 'prefer-cache']
      src_peer:
        aliases: ['src-peer']
        type: list
        elements: dict
        description: Src peer.
        suboptions:
          auth_type:
            aliases: ['auth-type']
            type: int
            description: Set authentication type for this peer.
          device_id:
            aliases: ['device-id']
            type: str
            description: Device ID of this peer.
          encode_type:
            aliases: ['encode-type']
            type: int
            description: Set encode type for this peer.
          ip:
            type: str
            description: Set cluster IP address of this peer.
          priority:
            type: int
            description: Set priority for this peer.
      prefer_senario:
        aliases: ['prefer-senario']
        type: str
        description: Prefer senario
        choices: ['balance', 'prefer-speed', 'prefer-cache']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Designate cache-service for wan-optimization and webcache.
      fortinet.fmgdevice.fmgd_wanopt_cacheservice:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        wanopt_cacheservice:
          # acceptable_connections: <value in [any, peers]>
          # collaboration: <value in [disable, enable]>
          # device_id: <string>
          # dst_peer:
          #   - auth_type: <integer>
          #     device_id: <string>
          #     encode_type: <integer>
          #     ip: <string>
          #     priority: <integer>
          # prefer_scenario: <value in [balance, prefer-speed, prefer-cache]>
          # src_peer:
          #   - auth_type: <integer>
          #     device_id: <string>
          #     encode_type: <integer>
          #     ip: <string>
          #     priority: <integer>
          # prefer_senario: <value in [balance, prefer-speed, prefer-cache]>
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
        '/pm/config/device/{device}/global/wanopt/cache-service',
        '/pm/config/device/{device}/vdom/{vdom}/wanopt/cache-service'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wanopt_cacheservice': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'acceptable-connections': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['any', 'peers'], 'type': 'str'},
                'collaboration': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'device-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'dst-peer': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'auth-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'device-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'encode-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'prefer-scenario': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['balance', 'prefer-speed', 'prefer-cache'],
                    'type': 'str'
                },
                'src-peer': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'auth-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'device-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'encode-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'prefer-senario': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['balance', 'prefer-speed', 'prefer-cache'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanopt_cacheservice'),
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
