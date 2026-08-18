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
module: fmgd_system_speedtestschedule
short_description: Speed test schedule for each interface.
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
  system_speedtestschedule:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      ctrl_port:
        aliases: ['ctrl-port']
        type: int
        description: Port of the controller to get access token.
      diffserv:
        type: str
        description: DSCP used for speed test.
      dynamic_server:
        aliases: ['dynamic-server']
        type: str
        description: Enable/disable dynamic server option.
        choices: ['disable', 'enable']
      interface:
        type: list
        elements: str
        description: Interface name.
      mode:
        type: str
        description: Protocol Auto
        choices: ['UDP', 'TCP', 'Auto']
      schedules:
        type: list
        elements: str
        description: Schedules for the interface.
      server_name:
        aliases: ['server-name']
        type: str
        description: Speed test server name.
      server_port:
        aliases: ['server-port']
        type: int
        description: Port of the server to run speed test.
      status:
        type: str
        description: Enable/disable scheduled speed test.
        choices: ['disable', 'enable']
      update_inbandwidth:
        aliases: ['update-inbandwidth']
        type: str
        description: Enable/disable bypassing interfaces inbound bandwidth setting.
        choices: ['disable', 'enable']
      update_inbandwidth_maximum:
        aliases: ['update-inbandwidth-maximum']
        type: int
        description: Maximum downloading bandwidth
      update_inbandwidth_minimum:
        aliases: ['update-inbandwidth-minimum']
        type: int
        description: Minimum downloading bandwidth
      update_outbandwidth:
        aliases: ['update-outbandwidth']
        type: str
        description: Enable/disable bypassing interfaces outbound bandwidth setting.
        choices: ['disable', 'enable']
      update_outbandwidth_maximum:
        aliases: ['update-outbandwidth-maximum']
        type: int
        description: Maximum uploading bandwidth
      update_outbandwidth_minimum:
        aliases: ['update-outbandwidth-minimum']
        type: int
        description: Minimum uploading bandwidth
      update_shaper:
        aliases: ['update-shaper']
        type: str
        description: Set egress shaper based on the test result.
        choices: ['disable', 'local', 'remote', 'both']
      expected_inbandwidth_maximum:
        aliases: ['expected-inbandwidth-maximum']
        type: int
        description: Set the maximum inbandwidth threshold for applying speedtest results on shaping-profile.
      expected_outbandwidth_minimum:
        aliases: ['expected-outbandwidth-minimum']
        type: int
        description: Set the minimum outbandwidth threshold for applying speedtest results on shaping-profile.
      retry_pause:
        aliases: ['retry-pause']
        type: int
        description: Number of seconds the FortiGate pauses between successive speed tests before trying a different server
      expected_outbandwidth_maximum:
        aliases: ['expected-outbandwidth-maximum']
        type: int
        description: Set the maximum outbandwidth threshold for applying speedtest results on shaping-profile.
      retries:
        type: int
        description: Maximum number of times the FortiGate unit will attempt to contact the same server before considering the speed test has failed
      update_interface_shaping:
        aliases: ['update-interface-shaping']
        type: str
        description: Enable/disable using the speedtest results as reference for interface shaping
        choices: ['disable', 'enable']
      expected_inbandwidth_minimum:
        aliases: ['expected-inbandwidth-minimum']
        type: int
        description: Set the minimum inbandwidth threshold for applying speedtest results on shaping-profile.
      legacy_server_mode:
        aliases: ['legacy-server-mode']
        type: str
        description: Legacy test server selection.
        choices: ['disable', 'enable']
      update_bandwidth_limit_unit:
        aliases: ['update-bandwidth-limit-unit']
        type: str
        description: Set the update bandwidth limits by values in kbps or percentages of interfaces bandwidth.
        choices: ['value', 'percentage']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Speed test schedule for each interface.
      fortinet.fmgdevice.fmgd_system_speedtestschedule:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        system_speedtestschedule:
          # ctrl_port: <integer>
          # diffserv: <string>
          # dynamic_server: <value in [disable, enable]>
          # interface: <list or string>
          # mode: <value in [UDP, TCP, Auto]>
          # schedules: <list or string>
          # server_name: <string>
          # server_port: <integer>
          # status: <value in [disable, enable]>
          # update_inbandwidth: <value in [disable, enable]>
          # update_inbandwidth_maximum: <integer>
          # update_inbandwidth_minimum: <integer>
          # update_outbandwidth: <value in [disable, enable]>
          # update_outbandwidth_maximum: <integer>
          # update_outbandwidth_minimum: <integer>
          # update_shaper: <value in [disable, local, remote, ...]>
          # expected_inbandwidth_maximum: <integer>
          # expected_outbandwidth_minimum: <integer>
          # retry_pause: <integer>
          # expected_outbandwidth_maximum: <integer>
          # retries: <integer>
          # update_interface_shaping: <value in [disable, enable]>
          # expected_inbandwidth_minimum: <integer>
          # legacy_server_mode: <value in [disable, enable]>
          # update_bandwidth_limit_unit: <value in [value, percentage]>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/speed-test-schedule'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_speedtestschedule': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'ctrl-port': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'diffserv': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'dynamic-server': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['UDP', 'TCP', 'Auto'], 'type': 'str'},
                'schedules': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'server-name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'server-port': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-inbandwidth': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-inbandwidth-maximum': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'update-inbandwidth-minimum': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'update-outbandwidth': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-outbandwidth-maximum': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'update-outbandwidth-minimum': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'update-shaper': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'local', 'remote', 'both'], 'type': 'str'},
                'expected-inbandwidth-maximum': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'expected-outbandwidth-minimum': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'retry-pause': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'expected-outbandwidth-maximum': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'retries': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'update-interface-shaping': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'expected-inbandwidth-minimum': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'legacy-server-mode': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-bandwidth-limit-unit': {'v_range': [['8.0.0', '']], 'choices': ['value', 'percentage'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_speedtestschedule'),
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
