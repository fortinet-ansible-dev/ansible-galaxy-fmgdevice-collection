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
module: fmgd_system_virtualwanlink_healthcheck
short_description: SD-WAN status checking or health checking.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    device:
        description: The parameter (device) in requested url.
        type: str
        required: true
    vdom:
        description: The parameter (vdom) in requested url.
        type: str
        required: true
    system_virtualwanlink_healthcheck:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            addr_mode:
                aliases: ['addr-mode']
                type: str
                description: Address mode
                choices:
                    - 'ipv4'
                    - 'ipv6'
            diffservcode:
                type: str
                description: Differentiated services code point
            failtime:
                type: int
                description:
                    - Support meta variable
                    - Number of failures before server is considered lost
            ha_priority:
                aliases: ['ha-priority']
                type: int
                description: HA election priority
            http_agent:
                aliases: ['http-agent']
                type: str
                description: String in the http-agent field in the HTTP header.
            http_get:
                aliases: ['http-get']
                type: str
                description: URL used to communicate with the server if the protocol if the protocol is HTTP.
            http_match:
                aliases: ['http-match']
                type: str
                description: Response string expected from the server if the protocol is HTTP.
            interval:
                type: int
                description:
                    - Support meta variable
                    - Status check interval in milliseconds, or the time between attempting to connect to the server
            members:
                type: list
                elements: str
                description: Member sequence number list.
            name:
                type: str
                description: Status check or health check name.
                required: true
            packet_size:
                aliases: ['packet-size']
                type: int
                description: Packet size of a twamp test session,
            password:
                type: list
                elements: str
                description: Twamp controller password in authentication mode
            port:
                type: int
                description: Port number used to communicate with the server over the selected protocol.
            probe_packets:
                aliases: ['probe-packets']
                type: str
                description: Enable/disable transmission of probe packets.
                choices:
                    - 'disable'
                    - 'enable'
            probe_timeout:
                aliases: ['probe-timeout']
                type: int
                description: Time to wait before a probe packet is considered lost
            protocol:
                type: str
                description: Protocol used to determine if the FortiGate can communicate with the server.
                choices:
                    - 'ping'
                    - 'tcp-echo'
                    - 'udp-echo'
                    - 'http'
                    - 'twamp'
                    - 'ping6'
                    - 'dns'
            recoverytime:
                type: int
                description:
                    - Support meta variable
                    - Number of successful responses received before server is considered recovered
            security_mode:
                aliases: ['security-mode']
                type: str
                description: Twamp controller security mode.
                choices:
                    - 'none'
                    - 'authentication'
            server:
                type: list
                elements: str
                description:
                    - Support meta variable
                    - IP address or FQDN name of the server.
            sla:
                type: list
                elements: dict
                description: Sla.
                suboptions:
                    id:
                        type: int
                        description: SLA ID.
                    jitter_threshold:
                        aliases: ['jitter-threshold']
                        type: int
                        description:
                            - Support meta variable
                            - Jitter for SLA to make decision in milliseconds.
                    latency_threshold:
                        aliases: ['latency-threshold']
                        type: int
                        description:
                            - Support meta variable
                            - Latency for SLA to make decision in milliseconds.
                    link_cost_factor:
                        aliases: ['link-cost-factor']
                        type: list
                        elements: str
                        description: Criteria on which to base link selection.
                        choices:
                            - 'latency'
                            - 'jitter'
                            - 'packet-loss'
                    packetloss_threshold:
                        aliases: ['packetloss-threshold']
                        type: int
                        description:
                            - Support meta variable
                            - Packet loss for SLA to make decision in percentage.
            sla_fail_log_period:
                aliases: ['sla-fail-log-period']
                type: int
                description: Time interval in seconds that SLA fail log messages will be generated
            sla_pass_log_period:
                aliases: ['sla-pass-log-period']
                type: int
                description: Time interval in seconds that SLA pass log messages will be generated
            threshold_alert_jitter:
                aliases: ['threshold-alert-jitter']
                type: int
                description: Alert threshold for jitter
            threshold_alert_latency:
                aliases: ['threshold-alert-latency']
                type: int
                description: Alert threshold for latency
            threshold_alert_packetloss:
                aliases: ['threshold-alert-packetloss']
                type: int
                description: Alert threshold for packet loss
            threshold_warning_jitter:
                aliases: ['threshold-warning-jitter']
                type: int
                description: Warning threshold for jitter
            threshold_warning_latency:
                aliases: ['threshold-warning-latency']
                type: int
                description: Warning threshold for latency
            threshold_warning_packetloss:
                aliases: ['threshold-warning-packetloss']
                type: int
                description: Warning threshold for packet loss
            update_cascade_interface:
                aliases: ['update-cascade-interface']
                type: str
                description: Enable/disable update cascade interface.
                choices:
                    - 'disable'
                    - 'enable'
            update_static_route:
                aliases: ['update-static-route']
                type: str
                description: Enable/disable updating the static route.
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: SD-WAN status checking or health checking.
      fortinet.fmgdevice.fmgd_system_virtualwanlink_healthcheck:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        system_virtualwanlink_healthcheck:
          name: "your value" # Required variable, string
          # addr_mode: <value in [ipv4, ipv6]>
          # diffservcode: <string>
          # failtime: <integer>
          # ha_priority: <integer>
          # http_agent: <string>
          # http_get: <string>
          # http_match: <string>
          # interval: <integer>
          # members: <list or string>
          # packet_size: <integer>
          # password: <list or string>
          # port: <integer>
          # probe_packets: <value in [disable, enable]>
          # probe_timeout: <integer>
          # protocol: <value in [ping, tcp-echo, udp-echo, ...]>
          # recoverytime: <integer>
          # security_mode: <value in [none, authentication]>
          # server: <list or string>
          # sla:
          #   - id: <integer>
          #     jitter_threshold: <integer>
          #     latency_threshold: <integer>
          #     link_cost_factor:
          #       - "latency"
          #       - "jitter"
          #       - "packet-loss"
          #     packetloss_threshold: <integer>
          # sla_fail_log_period: <integer>
          # sla_pass_log_period: <integer>
          # threshold_alert_jitter: <integer>
          # threshold_alert_latency: <integer>
          # threshold_alert_packetloss: <integer>
          # threshold_warning_jitter: <integer>
          # threshold_warning_latency: <integer>
          # threshold_warning_packetloss: <integer>
          # update_cascade_interface: <value in [disable, enable]>
          # update_static_route: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/health-check'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_virtualwanlink_healthcheck': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'addr-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                'diffservcode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'failtime': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ha-priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'http-agent': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'http-get': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'http-match': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'members': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'packet-size': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'probe-packets': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'probe-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'protocol': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['ping', 'tcp-echo', 'udp-echo', 'http', 'twamp', 'ping6', 'dns'],
                    'type': 'str'
                },
                'recoverytime': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'security-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'authentication'], 'type': 'str'},
                'server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'sla': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'jitter-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'latency-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'link-cost-factor': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': ['latency', 'jitter', 'packet-loss'],
                            'elements': 'str'
                        },
                        'packetloss-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'sla-fail-log-period': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'sla-pass-log-period': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                'threshold-alert-jitter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'threshold-alert-latency': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'threshold-alert-packetloss': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'threshold-warning-jitter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'threshold-warning-latency': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'threshold-warning-packetloss': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'update-cascade-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-static-route': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_virtualwanlink_healthcheck'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
