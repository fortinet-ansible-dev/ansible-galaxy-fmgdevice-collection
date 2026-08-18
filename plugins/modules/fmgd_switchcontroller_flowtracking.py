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
module: fmgd_switchcontroller_flowtracking
short_description: Configure FortiSwitch flow tracking and export via ipfix/netflow.
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
  switchcontroller_flowtracking:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      aggregates:
        type: list
        elements: dict
        description: Aggregates.
        suboptions:
          id:
            type: int
            description: Aggregate id.
          ip:
            type: list
            elements: str
            description: IP address to group all matching traffic sessions to a flow.
      collectors:
        type: list
        elements: dict
        description: Collectors.
        suboptions:
          ip:
            type: str
            description: Collector IP address.
          name:
            type: str
            description: Collector name.
          port:
            type: int
            description: Collector port number
          transport:
            type: str
            description: Collector L4 transport protocol for exporting packets.
            choices: ['udp', 'tcp', 'sctp']
      format:
        type: str
        description: Configure flow tracking protocol.
        choices: ['netflow1', 'netflow5', 'netflow9', 'ipfix']
      level:
        type: str
        description: Configure flow tracking level.
        choices: ['vlan', 'ip', 'port', 'proto', 'mac']
      max_export_pkt_size:
        aliases: ['max-export-pkt-size']
        type: int
        description: Configure flow max export packet size
      sample_mode:
        aliases: ['sample-mode']
        type: str
        description: Configure sample mode for the flow tracking.
        choices: ['local', 'perimeter', 'device-ingress']
      sample_rate:
        aliases: ['sample-rate']
        type: int
        description: Configure sample rate for the perimeter and device-ingress sampling
      template_export_period:
        aliases: ['template-export-period']
        type: int
        description: Configure template export period
      timeout_general:
        aliases: ['timeout-general']
        type: int
        description: Configure flow session general timeout
      timeout_icmp:
        aliases: ['timeout-icmp']
        type: int
        description: Configure flow session ICMP timeout
      timeout_max:
        aliases: ['timeout-max']
        type: int
        description: Configure flow session max timeout
      timeout_tcp:
        aliases: ['timeout-tcp']
        type: int
        description: Configure flow session TCP timeout
      timeout_tcp_fin:
        aliases: ['timeout-tcp-fin']
        type: int
        description: Configure flow session TCP FIN timeout
      timeout_tcp_rst:
        aliases: ['timeout-tcp-rst']
        type: int
        description: Configure flow session TCP RST timeout
      timeout_udp:
        aliases: ['timeout-udp']
        type: int
        description: Configure flow session UDP timeout
      transport:
        type: str
        description: Configure L4 transport protocol for exporting packets.
        choices: ['udp', 'tcp', 'sctp']
      collector_port:
        aliases: ['collector-port']
        type: int
        description: Configure collector port number
      collector_ip:
        aliases: ['collector-ip']
        type: str
        description: Configure collector ip address.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure FortiSwitch flow tracking and export via ipfix/netflow.
      fortinet.fmgdevice.fmgd_switchcontroller_flowtracking:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        switchcontroller_flowtracking:
          # aggregates:
          #   - id: <integer>
          #     ip: <list or string>
          # collectors:
          #   - ip: <string>
          #     name: <string>
          #     port: <integer>
          #     transport: <value in [udp, tcp, sctp]>
          # format: <value in [netflow1, netflow5, netflow9, ...]>
          # level: <value in [vlan, ip, port, ...]>
          # max_export_pkt_size: <integer>
          # sample_mode: <value in [local, perimeter, device-ingress]>
          # sample_rate: <integer>
          # template_export_period: <integer>
          # timeout_general: <integer>
          # timeout_icmp: <integer>
          # timeout_max: <integer>
          # timeout_tcp: <integer>
          # timeout_tcp_fin: <integer>
          # timeout_tcp_rst: <integer>
          # timeout_udp: <integer>
          # transport: <value in [udp, tcp, sctp]>
          # collector_port: <integer>
          # collector_ip: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/flow-tracking'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'switchcontroller_flowtracking': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'aggregates': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'collectors': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'transport': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['udp', 'tcp', 'sctp'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'format': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['netflow1', 'netflow5', 'netflow9', 'ipfix'], 'type': 'str'},
                'level': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['vlan', 'ip', 'port', 'proto', 'mac'], 'type': 'str'},
                'max-export-pkt-size': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'sample-mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['local', 'perimeter', 'device-ingress'], 'type': 'str'},
                'sample-rate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'template-export-period': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'timeout-general': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'timeout-icmp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'timeout-max': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'timeout-tcp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'timeout-tcp-fin': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'timeout-tcp-rst': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'timeout-udp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'transport': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['udp', 'tcp', 'sctp'], 'type': 'str'},
                'collector-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'collector-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_flowtracking'),
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
