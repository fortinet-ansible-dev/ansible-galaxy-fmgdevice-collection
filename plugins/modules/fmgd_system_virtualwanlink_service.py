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
module: fmgd_system_virtualwanlink_service
short_description: Create SD-WAN rules
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
    system_virtualwanlink_service:
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
            bandwidth_weight:
                aliases: ['bandwidth-weight']
                type: int
                description: Coefficient of reciprocal of available bidirectional bandwidth in the formula of custom-profile-1.
            default:
                type: str
                description: Enable/disable use of SD-WAN as default service.
                choices:
                    - 'disable'
                    - 'enable'
            dscp_forward:
                aliases: ['dscp-forward']
                type: str
                description: Enable/disable forward traffic DSCP tag.
                choices:
                    - 'disable'
                    - 'enable'
            dscp_forward_tag:
                aliases: ['dscp-forward-tag']
                type: str
                description: Forward traffic DSCP tag.
            dscp_reverse:
                aliases: ['dscp-reverse']
                type: str
                description: Enable/disable reverse traffic DSCP tag.
                choices:
                    - 'disable'
                    - 'enable'
            dscp_reverse_tag:
                aliases: ['dscp-reverse-tag']
                type: str
                description: Reverse traffic DSCP tag.
            dst:
                type: list
                elements: str
                description: Destination address name.
            dst_negate:
                aliases: ['dst-negate']
                type: str
                description: Enable/disable negation of destination address match.
                choices:
                    - 'disable'
                    - 'enable'
            dst6:
                type: list
                elements: str
                description: Destination address6 name.
            end_port:
                aliases: ['end-port']
                type: int
                description: End destination port number.
            gateway:
                type: str
                description: Enable/disable SD-WAN service gateway.
                choices:
                    - 'disable'
                    - 'enable'
            groups:
                type: list
                elements: str
                description: User groups.
            health_check:
                aliases: ['health-check']
                type: list
                elements: str
                description: Health check.
            hold_down_time:
                aliases: ['hold-down-time']
                type: int
                description: Waiting period in seconds when switching from the back-up member to the primary member
            id:
                type: int
                description: Priority rule ID
                required: true
            input_device:
                aliases: ['input-device']
                type: list
                elements: str
                description: Source interface name.
            input_device_negate:
                aliases: ['input-device-negate']
                type: str
                description: Enable/disable negation of input device match.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service:
                aliases: ['internet-service']
                type: str
                description: Enable/disable use of Internet service for application-based load balancing.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_app_ctrl:
                aliases: ['internet-service-app-ctrl']
                type: list
                elements: int
                description: Application control based Internet Service ID list.
            internet_service_app_ctrl_group:
                aliases: ['internet-service-app-ctrl-group']
                type: list
                elements: str
                description: Application control based Internet Service group list.
            internet_service_custom:
                aliases: ['internet-service-custom']
                type: list
                elements: str
                description: Custom Internet service name list.
            internet_service_custom_group:
                aliases: ['internet-service-custom-group']
                type: list
                elements: str
                description: Custom Internet Service group list.
            internet_service_group:
                aliases: ['internet-service-group']
                type: list
                elements: str
                description: Internet Service group list.
            internet_service_id:
                aliases: ['internet-service-id']
                type: list
                elements: str
                description: Internet service ID list.
            jitter_weight:
                aliases: ['jitter-weight']
                type: int
                description: Coefficient of jitter in the formula of custom-profile-1.
            latency_weight:
                aliases: ['latency-weight']
                type: int
                description: Coefficient of latency in the formula of custom-profile-1.
            link_cost_factor:
                aliases: ['link-cost-factor']
                type: str
                description: Link cost factor.
                choices:
                    - 'latency'
                    - 'jitter'
                    - 'packet-loss'
                    - 'inbandwidth'
                    - 'outbandwidth'
                    - 'bibandwidth'
                    - 'custom-profile-1'
            link_cost_threshold:
                aliases: ['link-cost-threshold']
                type: int
                description: Percentage threshold change of link cost values that will result in policy route regeneration
            mode:
                type: str
                description: Control how the priority rule sets the priority of interfaces in the SD-WAN.
                choices:
                    - 'auto'
                    - 'manual'
                    - 'priority'
                    - 'sla'
                    - 'load-balance'
            name:
                type: str
                description: Priority rule name.
            packet_loss_weight:
                aliases: ['packet-loss-weight']
                type: int
                description: Coefficient of packet-loss in the formula of custom-profile-1.
            priority_members:
                aliases: ['priority-members']
                type: list
                elements: str
                description: Member sequence number list.
            protocol:
                type: int
                description: Protocol number.
            quality_link:
                aliases: ['quality-link']
                type: int
                description: Quality grade.
            role:
                type: str
                description: Service role to work with neighbor.
                choices:
                    - 'primary'
                    - 'secondary'
                    - 'standalone'
            route_tag:
                aliases: ['route-tag']
                type: int
                description: IPv4 route map route-tag.
            sla:
                type: list
                elements: dict
                description: Sla.
                suboptions:
                    health_check:
                        aliases: ['health-check']
                        type: str
                        description: Virtual WAN Link health-check.
                    id:
                        type: int
                        description: SLA ID.
            sla_compare_method:
                aliases: ['sla-compare-method']
                type: str
                description: Method to compare SLA value for sla and load balance mode.
                choices:
                    - 'order'
                    - 'number'
            src:
                type: list
                elements: str
                description: Source address name.
            src_negate:
                aliases: ['src-negate']
                type: str
                description: Enable/disable negation of source address match.
                choices:
                    - 'disable'
                    - 'enable'
            src6:
                type: list
                elements: str
                description: Source address6 name.
            standalone_action:
                aliases: ['standalone-action']
                type: str
                description: Enable/disable service when selected neighbor role is standalone while service role is not standalone.
                choices:
                    - 'disable'
                    - 'enable'
            start_port:
                aliases: ['start-port']
                type: int
                description: Start destination port number.
            status:
                type: str
                description: Enable/disable SD-WAN service.
                choices:
                    - 'disable'
                    - 'enable'
            tos:
                type: str
                description: Type of service bit pattern.
            tos_mask:
                aliases: ['tos-mask']
                type: str
                description: Type of service evaluated bits.
            users:
                type: list
                elements: str
                description: User name.
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
    - name: Create SD-WAN rules
      fortinet.fmgdevice.fmgd_system_virtualwanlink_service:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        system_virtualwanlink_service:
          id: 0 # Required variable, integer
          # addr_mode: <value in [ipv4, ipv6]>
          # bandwidth_weight: <integer>
          # default: <value in [disable, enable]>
          # dscp_forward: <value in [disable, enable]>
          # dscp_forward_tag: <string>
          # dscp_reverse: <value in [disable, enable]>
          # dscp_reverse_tag: <string>
          # dst: <list or string>
          # dst_negate: <value in [disable, enable]>
          # dst6: <list or string>
          # end_port: <integer>
          # gateway: <value in [disable, enable]>
          # groups: <list or string>
          # health_check: <list or string>
          # hold_down_time: <integer>
          # input_device: <list or string>
          # input_device_negate: <value in [disable, enable]>
          # internet_service: <value in [disable, enable]>
          # internet_service_app_ctrl: <list or integer>
          # internet_service_app_ctrl_group: <list or string>
          # internet_service_custom: <list or string>
          # internet_service_custom_group: <list or string>
          # internet_service_group: <list or string>
          # internet_service_id: <list or string>
          # jitter_weight: <integer>
          # latency_weight: <integer>
          # link_cost_factor: <value in [latency, jitter, packet-loss, ...]>
          # link_cost_threshold: <integer>
          # mode: <value in [auto, manual, priority, ...]>
          # name: <string>
          # packet_loss_weight: <integer>
          # priority_members: <list or string>
          # protocol: <integer>
          # quality_link: <integer>
          # role: <value in [primary, secondary, standalone]>
          # route_tag: <integer>
          # sla:
          #   - health_check: <string>
          #     id: <integer>
          # sla_compare_method: <value in [order, number]>
          # src: <list or string>
          # src_negate: <value in [disable, enable]>
          # src6: <list or string>
          # standalone_action: <value in [disable, enable]>
          # start_port: <integer>
          # status: <value in [disable, enable]>
          # tos: <string>
          # tos_mask: <string>
          # users: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/service'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'id'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_virtualwanlink_service': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'addr-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                'bandwidth-weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'default': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dscp-forward': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dscp-forward-tag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dscp-reverse': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dscp-reverse-tag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dst': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dst-negate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dst6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'end-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'gateway': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'groups': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'health-check': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'hold-down-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'input-device': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'input-device-negate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-app-ctrl': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'internet-service-app-ctrl-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-custom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-custom-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'jitter-weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'latency-weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'link-cost-factor': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['latency', 'jitter', 'packet-loss', 'inbandwidth', 'outbandwidth', 'bibandwidth', 'custom-profile-1'],
                    'type': 'str'
                },
                'link-cost-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['auto', 'manual', 'priority', 'sla', 'load-balance'], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'packet-loss-weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'priority-members': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'protocol': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'quality-link': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'role': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['primary', 'secondary', 'standalone'], 'type': 'str'},
                'route-tag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'sla': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'health-check': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'sla-compare-method': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['order', 'number'], 'type': 'str'},
                'src': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'src-negate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'src6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'standalone-action': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'start-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tos': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'tos-mask': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'users': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_virtualwanlink_service'),
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
