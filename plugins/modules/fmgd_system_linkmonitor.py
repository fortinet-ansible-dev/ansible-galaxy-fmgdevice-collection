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
module: fmgd_system_linkmonitor
short_description: Configure Link Health Monitor.
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
  system_linkmonitor:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      addr_mode:
        aliases: ['addr-mode']
        type: str
        description: Address mode
        choices: ['ipv4', 'ipv6']
      class_id:
        aliases: ['class-id']
        type: list
        elements: str
        description: Traffic class ID.
      diffservcode:
        type: str
        description: Differentiated services code point
      fail_weight:
        aliases: ['fail-weight']
        type: int
        description: Threshold weight to trigger link failure alert.
      failtime:
        type: int
        description: Number of retry attempts before the server is considered down
      gateway_ip:
        aliases: ['gateway-ip']
        type: str
        description: Gateway IP address used to probe the server.
      gateway_ip6:
        aliases: ['gateway-ip6']
        type: str
        description: Gateway IPv6 address used to probe the server.
      http_agent:
        aliases: ['http-agent']
        type: str
        description: String in the http-agent field in the HTTP header.
      http_get:
        aliases: ['http-get']
        type: str
        description: If you are monitoring an HTML server you can send an HTTP-GET request with a custom string.
      http_match:
        aliases: ['http-match']
        type: str
        description: String that you expect to see in the HTTP-GET requests of the traffic to be monitored.
      interval:
        type: int
        description: Detection interval in milliseconds
      name:
        type: str
        description: Link monitor name.
        required: true
      packet_size:
        aliases: ['packet-size']
        type: int
        description: Packet size of a TWAMP test session
      password:
        type: list
        elements: str
        description: TWAMP controller password in authentication mode.
      port:
        type: int
        description: Port number of the traffic to be used to monitor the server.
      probe_count:
        aliases: ['probe-count']
        type: int
        description: Number of most recent probes that should be used to calculate latency and jitter
      probe_timeout:
        aliases: ['probe-timeout']
        type: int
        description: Time to wait before a probe packet is considered lost
      protocol:
        type: list
        elements: str
        description: Protocols used to monitor the server.
        choices: ['ping', 'tcp-echo', 'udp-echo', 'http', 'twamp', 'ping6', 'https']
      recoverytime:
        type: int
        description: Number of successful responses received before server is considered recovered
      route:
        type: list
        elements: str
        description: Subnet to monitor.
      security_mode:
        aliases: ['security-mode']
        type: str
        description: Twamp controller security mode.
        choices: ['none', 'authentication']
      server:
        type: list
        elements: str
        description: IP address of the server
      server_config:
        aliases: ['server-config']
        type: str
        description: Mode of server configuration.
        choices: ['default', 'individual']
      server_list:
        aliases: ['server-list']
        type: list
        elements: dict
        description: Server list.
        suboptions:
          dst:
            type: str
            description: IP address of the server to be monitored.
          id:
            type: int
            description: Server ID.
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
      server_type:
        aliases: ['server-type']
        type: str
        description: Server type
        choices: ['static', 'dynamic']
      service_detection:
        aliases: ['service-detection']
        type: str
        description: Only use monitor to read quality values.
        choices: ['disable', 'enable']
      source_ip:
        aliases: ['source-ip']
        type: str
        description: Source IP address used in packet to the server.
      source_ip6:
        aliases: ['source-ip6']
        type: str
        description: Source IPv6 address used in packet to the server.
      srcintf:
        type: list
        elements: str
        description: Interface that receives the traffic to be monitored.
      status:
        type: str
        description: Enable/disable this link monitor.
        choices: ['disable', 'enable']
      update_cascade_interface:
        aliases: ['update-cascade-interface']
        type: str
        description: Enable/disable update cascade interface.
        choices: ['disable', 'enable']
      update_policy_route:
        aliases: ['update-policy-route']
        type: str
        description: Enable/disable updating the policy route.
        choices: ['disable', 'enable']
      update_static_route:
        aliases: ['update-static-route']
        type: str
        description: Enable/disable updating the static route.
        choices: ['disable', 'enable']
      ha_priority:
        aliases: ['ha-priority']
        type: int
        description: HA election priority
      timeout:
        type: int
        description: Detection request timeout
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure Link Health Monitor.
      fortinet.fmgdevice.fmgd_system_linkmonitor:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        system_linkmonitor:
          name: "your value" # Required variable, string
          # addr_mode: <value in [ipv4, ipv6]>
          # class_id: <list or string>
          # diffservcode: <string>
          # fail_weight: <integer>
          # failtime: <integer>
          # gateway_ip: <string>
          # gateway_ip6: <string>
          # http_agent: <string>
          # http_get: <string>
          # http_match: <string>
          # interval: <integer>
          # packet_size: <integer>
          # password: <list or string>
          # port: <integer>
          # probe_count: <integer>
          # probe_timeout: <integer>
          # protocol: ["ping", "tcp-echo", "udp-echo", "http", "twamp", "ping6", "https"]
          # recoverytime: <integer>
          # route: <list or string>
          # security_mode: <value in [none, authentication]>
          # server: <list or string>
          # server_config: <value in [default, individual]>
          # server_list:
          #   - dst: <string>
          #     id: <integer>
          #     port: <integer>
          #     protocol: ["ping", "tcp-echo", "udp-echo", "http", "twamp", "https"]
          #     weight: <integer>
          # server_type: <value in [static, dynamic]>
          # service_detection: <value in [disable, enable]>
          # source_ip: <string>
          # source_ip6: <string>
          # srcintf: <list or string>
          # status: <value in [disable, enable]>
          # update_cascade_interface: <value in [disable, enable]>
          # update_policy_route: <value in [disable, enable]>
          # update_static_route: <value in [disable, enable]>
          # ha_priority: <integer>
          # timeout: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/link-monitor'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_linkmonitor': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'addr-mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                'class-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'diffservcode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'fail-weight': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'failtime': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'gateway-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'gateway-ip6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'http-agent': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'http-get': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'http-match': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'packet-size': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'password': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'probe-count': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'probe-timeout': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'protocol': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['ping', 'tcp-echo', 'udp-echo', 'http', 'twamp', 'ping6', 'https'],
                    'elements': 'str'
                },
                'recoverytime': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'route': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'security-mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'authentication'], 'type': 'str'},
                'server': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'server-config': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['default', 'individual'], 'type': 'str'},
                'server-list': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'dst': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'protocol': {
                            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': ['ping', 'tcp-echo', 'udp-echo', 'http', 'twamp', 'https'],
                            'elements': 'str'
                        },
                        'weight': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'server-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['static', 'dynamic'], 'type': 'str'},
                'service-detection': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'source-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'source-ip6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'srcintf': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-cascade-interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-policy-route': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-static-route': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ha-priority': {'v_range': [['7.2.11', '7.2.12'], ['7.4.7', '7.4.11'], ['7.6.3', '']], 'type': 'int'},
                'timeout': {'v_range': [['7.4.8', '7.4.11']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_linkmonitor'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
