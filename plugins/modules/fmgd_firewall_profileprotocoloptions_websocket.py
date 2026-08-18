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
module: fmgd_firewall_profileprotocoloptions_websocket
short_description: Configure WebSocket protocol options.
version_added: "1.2.0"
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
  firewall_profileprotocoloptions_websocket:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      comfort_amount:
        aliases: ['comfort-amount']
        type: int
        description: Number of bytes to send in each transmission for client comforting
      comfort_interval:
        aliases: ['comfort-interval']
        type: int
        description: Interval between successive transmissions of data for client comforting
      options:
        type: list
        elements: str
        description: One or more options that can be applied to the session.
        choices: ['oversize', 'clientcomfort', 'servercomfort']
      oversize_limit:
        aliases: ['oversize-limit']
        type: int
        description: Maximum in-memory file size that can be scanned
      scan_bzip2:
        aliases: ['scan-bzip2']
        type: str
        description: Enable/disable scanning of BZip2 compressed files.
        choices: ['disable', 'enable']
      status:
        type: str
        description: Enable/disable the active status of scanning for this protocol.
        choices: ['disable', 'enable']
      stream_based_uncompressed_limit:
        aliases: ['stream-based-uncompressed-limit']
        type: int
        description: Maximum stream-based uncompressed data size that will be scanned in megabytes.
      tcp_window_maximum:
        aliases: ['tcp-window-maximum']
        type: int
        description: Maximum dynamic TCP window size.
      tcp_window_minimum:
        aliases: ['tcp-window-minimum']
        type: int
        description: Minimum dynamic TCP window size.
      tcp_window_size:
        aliases: ['tcp-window-size']
        type: int
        description: Set TCP static window size.
      tcp_window_type:
        aliases: ['tcp-window-type']
        type: str
        description: TCP window type to use for this protocol.
        choices: ['system', 'static', 'dynamic', 'auto-tuning']
      tunnel_non_websocket:
        aliases: ['tunnel-non-websocket']
        type: str
        description: Configure how to process non-websocket traffic when a profile configured for websocket traffic accepts a non-websocket session.
        choices: ['disable', 'enable']
      uncompressed_nest_limit:
        aliases: ['uncompressed-nest-limit']
        type: int
        description: Maximum nested levels of compression that can be uncompressed and scanned
      uncompressed_oversize_limit:
        aliases: ['uncompressed-oversize-limit']
        type: int
        description: Maximum in-memory uncompressed file size that can be scanned
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure WebSocket protocol options.
      fortinet.fmgdevice.fmgd_firewall_profileprotocoloptions_websocket:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        profile_protocol_options: <your own value>
        firewall_profileprotocoloptions_websocket:
          # comfort_amount: <integer>
          # comfort_interval: <integer>
          # options: ["oversize", "clientcomfort", "servercomfort"]
          # oversize_limit: <integer>
          # scan_bzip2: <value in [disable, enable]>
          # status: <value in [disable, enable]>
          # stream_based_uncompressed_limit: <integer>
          # tcp_window_maximum: <integer>
          # tcp_window_minimum: <integer>
          # tcp_window_size: <integer>
          # tcp_window_type: <value in [system, static, dynamic, ...]>
          # tunnel_non_websocket: <value in [disable, enable]>
          # uncompressed_nest_limit: <integer>
          # uncompressed_oversize_limit: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/profile-protocol-options/{profile-protocol-options}/websocket'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'profile-protocol-options': {'type': 'str', 'api_name': 'profile_protocol_options'},
        'profile_protocol_options': {'type': 'str'},
        'firewall_profileprotocoloptions_websocket': {
            'type': 'dict', 'v_range': [['7.6.7', '']],
            'options': {
                'comfort-amount': {'v_range': [['7.6.7', '']], 'type': 'int'},
                'comfort-interval': {'v_range': [['7.6.7', '']], 'type': 'int'},
                'options': {'v_range': [['7.6.7', '']], 'type': 'list', 'choices': ['oversize', 'clientcomfort', 'servercomfort'], 'elements': 'str'},
                'oversize-limit': {'v_range': [['7.6.7', '']], 'type': 'int'},
                'scan-bzip2': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'stream-based-uncompressed-limit': {'v_range': [['7.6.7', '']], 'type': 'int'},
                'tcp-window-maximum': {'v_range': [['7.6.7', '']], 'type': 'int'},
                'tcp-window-minimum': {'v_range': [['7.6.7', '']], 'type': 'int'},
                'tcp-window-size': {'v_range': [['7.6.7', '']], 'type': 'int'},
                'tcp-window-type': {'v_range': [['7.6.7', '']], 'choices': ['system', 'static', 'dynamic', 'auto-tuning'], 'type': 'str'},
                'tunnel-non-websocket': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uncompressed-nest-limit': {'v_range': [['7.6.7', '']], 'type': 'int'},
                'uncompressed-oversize-limit': {'v_range': [['7.6.7', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_profileprotocoloptions_websocket'),
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
