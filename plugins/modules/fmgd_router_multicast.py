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
module: fmgd_router_multicast
short_description: Configure router multicast.
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
    router_multicast:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            interface:
                type: list
                elements: dict
                description: Interface.
                suboptions:
                    bfd:
                        type: str
                        description: Enable/disable Protocol Independent Multicast
                        choices:
                            - 'disable'
                            - 'enable'
                    cisco_exclude_genid:
                        aliases: ['cisco-exclude-genid']
                        type: str
                        description: Exclude GenID from hello packets
                        choices:
                            - 'disable'
                            - 'enable'
                    dr_priority:
                        aliases: ['dr-priority']
                        type: int
                        description: DR election priority.
                    hello_holdtime:
                        aliases: ['hello-holdtime']
                        type: int
                        description: Time before old neighbor information expires
                    hello_interval:
                        aliases: ['hello-interval']
                        type: int
                        description: Interval between sending PIM hello messages
                    igmp:
                        type: dict
                        description: Igmp.
                        suboptions:
                            access_group:
                                aliases: ['access-group']
                                type: list
                                elements: str
                                description: Groups IGMP hosts are allowed to join.
                            immediate_leave_group:
                                aliases: ['immediate-leave-group']
                                type: list
                                elements: str
                                description: Groups to drop membership for immediately after receiving IGMPv2 leave.
                            last_member_query_count:
                                aliases: ['last-member-query-count']
                                type: int
                                description: Number of group specific queries before removing group
                            last_member_query_interval:
                                aliases: ['last-member-query-interval']
                                type: int
                                description: Timeout between IGMPv2 leave and removing group
                            query_interval:
                                aliases: ['query-interval']
                                type: int
                                description: Interval between queries to IGMP hosts
                            query_max_response_time:
                                aliases: ['query-max-response-time']
                                type: int
                                description: Maximum time to wait for a IGMP query response
                            query_timeout:
                                aliases: ['query-timeout']
                                type: int
                                description: Timeout between queries before becoming querying unit for network
                            router_alert_check:
                                aliases: ['router-alert-check']
                                type: str
                                description: Enable/disable require IGMP packets contain router alert option.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            version:
                                type: str
                                description: Maximum version of IGMP to support.
                                choices:
                                    - '1'
                                    - '2'
                                    - '3'
                    join_group:
                        aliases: ['join-group']
                        type: list
                        elements: dict
                        description: Join group.
                        suboptions:
                            address:
                                type: str
                                description: Multicast group IP address.
                    multicast_flow:
                        aliases: ['multicast-flow']
                        type: list
                        elements: str
                        description: Acceptable source for multicast group.
                    name:
                        type: str
                        description: Interface name.
                    neighbour_filter:
                        aliases: ['neighbour-filter']
                        type: list
                        elements: str
                        description: Routers acknowledged as neighbor routers.
                    passive:
                        type: str
                        description: Enable/disable listening to IGMP but not participating in PIM.
                        choices:
                            - 'disable'
                            - 'enable'
                    pim_mode:
                        aliases: ['pim-mode']
                        type: str
                        description: PIM operation mode.
                        choices:
                            - 'sparse-mode'
                            - 'dense-mode'
                    propagation_delay:
                        aliases: ['propagation-delay']
                        type: int
                        description: Delay flooding packets on this interface
                    rp_candidate:
                        aliases: ['rp-candidate']
                        type: str
                        description: Enable/disable compete to become RP in elections.
                        choices:
                            - 'disable'
                            - 'enable'
                    rp_candidate_group:
                        aliases: ['rp-candidate-group']
                        type: list
                        elements: str
                        description: Multicast groups managed by this RP.
                    rp_candidate_interval:
                        aliases: ['rp-candidate-interval']
                        type: int
                        description: RP candidate advertisement interval
                    rp_candidate_priority:
                        aliases: ['rp-candidate-priority']
                        type: int
                        description: Routers priority as RP.
                    rpf_nbr_fail_back:
                        aliases: ['rpf-nbr-fail-back']
                        type: str
                        description: Enable/disable fail back for RPF neighbor query.
                        choices:
                            - 'disable'
                            - 'enable'
                    rpf_nbr_fail_back_filter:
                        aliases: ['rpf-nbr-fail-back-filter']
                        type: list
                        elements: str
                        description: Filter for fail back RPF neighbors.
                    state_refresh_interval:
                        aliases: ['state-refresh-interval']
                        type: int
                        description: Interval between sending state-refresh packets
                    static_group:
                        aliases: ['static-group']
                        type: list
                        elements: str
                        description: Statically set multicast groups to forward out.
                    ttl_threshold:
                        aliases: ['ttl-threshold']
                        type: int
                        description: Minimum TTL of multicast packets that will be forwarded
            multicast_routing:
                aliases: ['multicast-routing']
                type: str
                description: Enable/disable IP multicast routing.
                choices:
                    - 'disable'
                    - 'enable'
            pim_sm_global:
                aliases: ['pim-sm-global']
                type: dict
                description: Pim sm global.
                suboptions:
                    accept_register_list:
                        aliases: ['accept-register-list']
                        type: list
                        elements: str
                        description: Sources allowed to register packets with this Rendezvous Point
                    accept_source_list:
                        aliases: ['accept-source-list']
                        type: list
                        elements: str
                        description: Sources allowed to send multicast traffic.
                    bsr_allow_quick_refresh:
                        aliases: ['bsr-allow-quick-refresh']
                        type: str
                        description: Enable/disable accept BSR quick refresh packets from neighbors.
                        choices:
                            - 'disable'
                            - 'enable'
                    bsr_candidate:
                        aliases: ['bsr-candidate']
                        type: str
                        description: Enable/disable allowing this router to become a bootstrap router
                        choices:
                            - 'disable'
                            - 'enable'
                    bsr_hash:
                        aliases: ['bsr-hash']
                        type: int
                        description: BSR hash length
                    bsr_interface:
                        aliases: ['bsr-interface']
                        type: list
                        elements: str
                        description: Interface to advertise as candidate BSR.
                    bsr_priority:
                        aliases: ['bsr-priority']
                        type: int
                        description: BSR priority
                    cisco_crp_prefix:
                        aliases: ['cisco-crp-prefix']
                        type: str
                        description: Enable/disable making candidate RP compatible with old Cisco IOS.
                        choices:
                            - 'disable'
                            - 'enable'
                    cisco_ignore_rp_set_priority:
                        aliases: ['cisco-ignore-rp-set-priority']
                        type: str
                        description: Use only hash for RP selection
                        choices:
                            - 'disable'
                            - 'enable'
                    cisco_register_checksum:
                        aliases: ['cisco-register-checksum']
                        type: str
                        description: Checksum entire register packet
                        choices:
                            - 'disable'
                            - 'enable'
                    cisco_register_checksum_group:
                        aliases: ['cisco-register-checksum-group']
                        type: list
                        elements: str
                        description: Cisco register checksum only these groups.
                    join_prune_holdtime:
                        aliases: ['join-prune-holdtime']
                        type: int
                        description: Join/prune holdtime
                    message_interval:
                        aliases: ['message-interval']
                        type: int
                        description: Period of time between sending periodic PIM join/prune messages in seconds
                    null_register_retries:
                        aliases: ['null-register-retries']
                        type: int
                        description: Maximum retries of null register
                    pim_use_sdwan:
                        aliases: ['pim-use-sdwan']
                        type: str
                        description: Enable/disable use of SDWAN when checking RPF neighbor and sending of REG packet.
                        choices:
                            - 'disable'
                            - 'enable'
                    register_rate_limit:
                        aliases: ['register-rate-limit']
                        type: int
                        description: Limit of packets/sec per source registered through this RP
                    register_rp_reachability:
                        aliases: ['register-rp-reachability']
                        type: str
                        description: Enable/disable check RP is reachable before registering packets.
                        choices:
                            - 'disable'
                            - 'enable'
                    register_source:
                        aliases: ['register-source']
                        type: str
                        description: Override source address in register packets.
                        choices:
                            - 'disable'
                            - 'ip-address'
                            - 'interface'
                    register_source_interface:
                        aliases: ['register-source-interface']
                        type: list
                        elements: str
                        description: Override with primary interface address.
                    register_source_ip:
                        aliases: ['register-source-ip']
                        type: str
                        description: Override with local IP address.
                    register_supression:
                        aliases: ['register-supression']
                        type: int
                        description: Period of time to honor register-stop message
                    rp_address:
                        aliases: ['rp-address']
                        type: list
                        elements: dict
                        description: Rp address.
                        suboptions:
                            group:
                                type: list
                                elements: str
                                description: Groups to use this RP.
                            id:
                                type: int
                                description: ID.
                            ip_address:
                                aliases: ['ip-address']
                                type: str
                                description: RP router address.
                    rp_register_keepalive:
                        aliases: ['rp-register-keepalive']
                        type: int
                        description: Timeout for RP receiving data on
                    spt_threshold:
                        aliases: ['spt-threshold']
                        type: str
                        description: Enable/disable switching to source specific trees.
                        choices:
                            - 'disable'
                            - 'enable'
                    spt_threshold_group:
                        aliases: ['spt-threshold-group']
                        type: list
                        elements: str
                        description: Groups allowed to switch to source tree.
                    ssm:
                        type: str
                        description: Enable/disable source specific multicast.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssm_range:
                        aliases: ['ssm-range']
                        type: list
                        elements: str
                        description: Groups allowed to source specific multicast.
            route_limit:
                aliases: ['route-limit']
                type: int
                description: Maximum number of multicast routes.
            route_threshold:
                aliases: ['route-threshold']
                type: int
                description: Generate warnings when the number of multicast routes exceeds this number, must not be greater than route-limit.
            pim_sm_global_vrf:
                aliases: ['pim-sm-global-vrf']
                type: list
                elements: dict
                description: Pim sm global vrf.
                suboptions:
                    bsr_allow_quick_refresh:
                        aliases: ['bsr-allow-quick-refresh']
                        type: str
                        description: Enable/disable accept BSR quick refresh packets from neighbors.
                        choices:
                            - 'disable'
                            - 'enable'
                    bsr_candidate:
                        aliases: ['bsr-candidate']
                        type: str
                        description: Enable/disable allowing this router to become a bootstrap router
                        choices:
                            - 'disable'
                            - 'enable'
                    bsr_hash:
                        aliases: ['bsr-hash']
                        type: int
                        description: BSR hash length
                    bsr_interface:
                        aliases: ['bsr-interface']
                        type: list
                        elements: str
                        description: Interface to advertise as candidate BSR.
                    bsr_priority:
                        aliases: ['bsr-priority']
                        type: int
                        description: BSR priority
                    cisco_crp_prefix:
                        aliases: ['cisco-crp-prefix']
                        type: str
                        description: Enable/disable making candidate RP compatible with old Cisco IOS.
                        choices:
                            - 'disable'
                            - 'enable'
                    rp_address:
                        aliases: ['rp-address']
                        type: list
                        elements: dict
                        description: Rp address.
                        suboptions:
                            group:
                                type: list
                                elements: str
                                description: Groups to use this RP.
                            id:
                                type: int
                                description: ID.
                            ip_address:
                                aliases: ['ip-address']
                                type: str
                                description: RP router address.
                    vrf:
                        type: int
                        description: VRF ID.
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
    - name: Configure router multicast.
      fortinet.fmgdevice.fmgd_router_multicast:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        router_multicast:
          # interface:
          #   - bfd: <value in [disable, enable]>
          #     cisco_exclude_genid: <value in [disable, enable]>
          #     dr_priority: <integer>
          #     hello_holdtime: <integer>
          #     hello_interval: <integer>
          #     igmp:
          #       access_group: <list or string>
          #       immediate_leave_group: <list or string>
          #       last_member_query_count: <integer>
          #       last_member_query_interval: <integer>
          #       query_interval: <integer>
          #       query_max_response_time: <integer>
          #       query_timeout: <integer>
          #       router_alert_check: <value in [disable, enable]>
          #       version: <value in [1, 2, 3]>
          #     join_group:
          #       - address: <string>
          #     multicast_flow: <list or string>
          #     name: <string>
          #     neighbour_filter: <list or string>
          #     passive: <value in [disable, enable]>
          #     pim_mode: <value in [sparse-mode, dense-mode]>
          #     propagation_delay: <integer>
          #     rp_candidate: <value in [disable, enable]>
          #     rp_candidate_group: <list or string>
          #     rp_candidate_interval: <integer>
          #     rp_candidate_priority: <integer>
          #     rpf_nbr_fail_back: <value in [disable, enable]>
          #     rpf_nbr_fail_back_filter: <list or string>
          #     state_refresh_interval: <integer>
          #     static_group: <list or string>
          #     ttl_threshold: <integer>
          # multicast_routing: <value in [disable, enable]>
          # pim_sm_global:
          #   accept_register_list: <list or string>
          #   accept_source_list: <list or string>
          #   bsr_allow_quick_refresh: <value in [disable, enable]>
          #   bsr_candidate: <value in [disable, enable]>
          #   bsr_hash: <integer>
          #   bsr_interface: <list or string>
          #   bsr_priority: <integer>
          #   cisco_crp_prefix: <value in [disable, enable]>
          #   cisco_ignore_rp_set_priority: <value in [disable, enable]>
          #   cisco_register_checksum: <value in [disable, enable]>
          #   cisco_register_checksum_group: <list or string>
          #   join_prune_holdtime: <integer>
          #   message_interval: <integer>
          #   null_register_retries: <integer>
          #   pim_use_sdwan: <value in [disable, enable]>
          #   register_rate_limit: <integer>
          #   register_rp_reachability: <value in [disable, enable]>
          #   register_source: <value in [disable, ip-address, interface]>
          #   register_source_interface: <list or string>
          #   register_source_ip: <string>
          #   register_supression: <integer>
          #   rp_address:
          #     - group: <list or string>
          #       id: <integer>
          #       ip_address: <string>
          #   rp_register_keepalive: <integer>
          #   spt_threshold: <value in [disable, enable]>
          #   spt_threshold_group: <list or string>
          #   ssm: <value in [disable, enable]>
          #   ssm_range: <list or string>
          # route_limit: <integer>
          # route_threshold: <integer>
          # pim_sm_global_vrf:
          #   - bsr_allow_quick_refresh: <value in [disable, enable]>
          #     bsr_candidate: <value in [disable, enable]>
          #     bsr_hash: <integer>
          #     bsr_interface: <list or string>
          #     bsr_priority: <integer>
          #     cisco_crp_prefix: <value in [disable, enable]>
          #     rp_address:
          #       - group: <list or string>
          #         id: <integer>
          #         ip_address: <string>
          #     vrf: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/multicast'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'router_multicast': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'interface': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'bfd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'cisco-exclude-genid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dr-priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'hello-holdtime': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'hello-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'igmp': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'dict',
                            'options': {
                                'access-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                                'immediate-leave-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                                'last-member-query-count': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'last-member-query-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'query-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'query-max-response-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'query-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'router-alert-check': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'version': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['1', '2', '3'], 'type': 'str'}
                            }
                        },
                        'join-group': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {'address': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}},
                            'elements': 'dict'
                        },
                        'multicast-flow': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'neighbour-filter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'passive': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pim-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['sparse-mode', 'dense-mode'], 'type': 'str'},
                        'propagation-delay': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'rp-candidate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'rp-candidate-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'rp-candidate-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'rp-candidate-priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'rpf-nbr-fail-back': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'rpf-nbr-fail-back-filter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'state-refresh-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'static-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'ttl-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'multicast-routing': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pim-sm-global': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'accept-register-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'accept-source-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'bsr-allow-quick-refresh': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bsr-candidate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bsr-hash': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'bsr-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'bsr-priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'cisco-crp-prefix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'cisco-ignore-rp-set-priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'cisco-register-checksum': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'cisco-register-checksum-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'join-prune-holdtime': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'message-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'null-register-retries': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'pim-use-sdwan': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'register-rate-limit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'register-rp-reachability': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'register-source': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['disable', 'ip-address', 'interface'],
                            'type': 'str'
                        },
                        'register-source-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'register-source-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'register-supression': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'rp-address': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'ip-address': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'rp-register-keepalive': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'spt-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'spt-threshold-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'ssm': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssm-range': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    }
                },
                'route-limit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'route-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'pim-sm-global-vrf': {
                    'v_range': [['7.6.2', '']],
                    'type': 'list',
                    'options': {
                        'bsr-allow-quick-refresh': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bsr-candidate': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bsr-hash': {'v_range': [['7.6.2', '']], 'type': 'int'},
                        'bsr-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                        'bsr-priority': {'v_range': [['7.6.2', '']], 'type': 'int'},
                        'cisco-crp-prefix': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'rp-address': {
                            'v_range': [['7.6.2', '']],
                            'type': 'list',
                            'options': {
                                'group': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                                'id': {'v_range': [['7.6.2', '']], 'type': 'int'},
                                'ip-address': {'v_range': [['7.6.2', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'vrf': {'v_range': [['7.6.2', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_multicast'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
