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
module: fmgd_router_ospf
short_description: Configure OSPF.
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
    router_ospf:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            abr_type:
                aliases: ['abr-type']
                type: str
                description: Area border router type.
                choices:
                    - 'cisco'
                    - 'ibm'
                    - 'shortcut'
                    - 'standard'
            area:
                type: list
                elements: dict
                description: Area.
                suboptions:
                    authentication:
                        type: str
                        description: Authentication type.
                        choices:
                            - 'none'
                            - 'text'
                            - 'md5'
                            - 'message-digest'
                    comments:
                        type: str
                        description: Comment.
                    default_cost:
                        aliases: ['default-cost']
                        type: int
                        description: Summary default cost of stub or NSSA area.
                    filter_list:
                        aliases: ['filter-list']
                        type: list
                        elements: dict
                        description: Filter list.
                        suboptions:
                            direction:
                                type: str
                                description: Direction.
                                choices:
                                    - 'out'
                                    - 'in'
                            id:
                                type: int
                                description: Filter list entry ID.
                            list:
                                type: list
                                elements: str
                                description: Access-list or prefix-list name.
                    id:
                        type: str
                        description: Area entry IP address.
                    nssa_default_information_originate:
                        aliases: ['nssa-default-information-originate']
                        type: str
                        description: Redistribute, advertise, or do not originate Type-7 default route into NSSA area.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'always'
                    nssa_default_information_originate_metric:
                        aliases: ['nssa-default-information-originate-metric']
                        type: int
                        description: OSPF default metric.
                    nssa_default_information_originate_metric_type:
                        aliases: ['nssa-default-information-originate-metric-type']
                        type: str
                        description: OSPF metric type for default routes.
                        choices:
                            - '2'
                            - '1'
                    nssa_redistribution:
                        aliases: ['nssa-redistribution']
                        type: str
                        description: Enable/disable redistribute into NSSA area.
                        choices:
                            - 'disable'
                            - 'enable'
                    nssa_translator_role:
                        aliases: ['nssa-translator-role']
                        type: str
                        description: NSSA translator role type.
                        choices:
                            - 'candidate'
                            - 'never'
                            - 'always'
                    range:
                        type: list
                        elements: dict
                        description: Range.
                        suboptions:
                            advertise:
                                type: str
                                description: Enable/disable advertise status.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            id:
                                type: int
                                description: Range entry ID.
                            prefix:
                                type: list
                                elements: str
                                description: Prefix.
                            substitute:
                                type: list
                                elements: str
                                description: Substitute prefix.
                            substitute_status:
                                aliases: ['substitute-status']
                                type: str
                                description: Enable/disable substitute status.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    shortcut:
                        type: str
                        description: Enable/disable shortcut option.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'default'
                    stub_type:
                        aliases: ['stub-type']
                        type: str
                        description: Stub summary setting.
                        choices:
                            - 'summary'
                            - 'no-summary'
                    type:
                        type: str
                        description: Area type setting.
                        choices:
                            - 'regular'
                            - 'nssa'
                            - 'stub'
                    virtual_link:
                        aliases: ['virtual-link']
                        type: list
                        elements: dict
                        description: Virtual link.
                        suboptions:
                            authentication:
                                type: str
                                description: Authentication type.
                                choices:
                                    - 'none'
                                    - 'text'
                                    - 'md5'
                                    - 'message-digest'
                            authentication_key:
                                aliases: ['authentication-key']
                                type: list
                                elements: str
                                description: Authentication key.
                            dead_interval:
                                aliases: ['dead-interval']
                                type: int
                                description: Dead interval.
                            hello_interval:
                                aliases: ['hello-interval']
                                type: int
                                description: Hello interval.
                            keychain:
                                type: list
                                elements: str
                                description: Message-digest key-chain name.
                            md5_keys:
                                aliases: ['md5-keys']
                                type: list
                                elements: dict
                                description: Md5 keys.
                                suboptions:
                                    id:
                                        type: int
                                        description: Key ID
                                    key_string:
                                        aliases: ['key-string']
                                        type: list
                                        elements: str
                                        description: Password for the key.
                            name:
                                type: str
                                description: Virtual link entry name.
                            peer:
                                type: str
                                description: Peer IP.
                            retransmit_interval:
                                aliases: ['retransmit-interval']
                                type: int
                                description: Retransmit interval.
                            transmit_delay:
                                aliases: ['transmit-delay']
                                type: int
                                description: Transmit delay.
                            md5_keychain:
                                aliases: ['md5-keychain']
                                type: list
                                elements: str
                                description: Authentication MD5 key-chain name.
            auto_cost_ref_bandwidth:
                aliases: ['auto-cost-ref-bandwidth']
                type: int
                description: Reference bandwidth in terms of megabits per second.
            bfd:
                type: str
                description: Bidirectional Forwarding Detection
                choices:
                    - 'disable'
                    - 'enable'
            database_overflow:
                aliases: ['database-overflow']
                type: str
                description: Enable/disable database overflow.
                choices:
                    - 'disable'
                    - 'enable'
            database_overflow_max_lsas:
                aliases: ['database-overflow-max-lsas']
                type: int
                description: Database overflow maximum LSAs.
            database_overflow_time_to_recover:
                aliases: ['database-overflow-time-to-recover']
                type: int
                description: Database overflow time to recover
            default_information_metric:
                aliases: ['default-information-metric']
                type: int
                description: Default information metric.
            default_information_metric_type:
                aliases: ['default-information-metric-type']
                type: str
                description: Default information metric type.
                choices:
                    - '2'
                    - '1'
            default_information_originate:
                aliases: ['default-information-originate']
                type: str
                description: Enable/disable generation of default route.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'always'
            default_information_route_map:
                aliases: ['default-information-route-map']
                type: list
                elements: str
                description: Default information route map.
            default_metric:
                aliases: ['default-metric']
                type: int
                description: Default metric of redistribute routes.
            distance:
                type: int
                description: Distance of the route.
            distance_external:
                aliases: ['distance-external']
                type: int
                description: Administrative external distance.
            distance_inter_area:
                aliases: ['distance-inter-area']
                type: int
                description: Administrative inter-area distance.
            distance_intra_area:
                aliases: ['distance-intra-area']
                type: int
                description: Administrative intra-area distance.
            distribute_list:
                aliases: ['distribute-list']
                type: list
                elements: dict
                description: Distribute list.
                suboptions:
                    access_list:
                        aliases: ['access-list']
                        type: list
                        elements: str
                        description: Access list name.
                    id:
                        type: int
                        description: Distribute list entry ID.
                    protocol:
                        type: str
                        description: Protocol type.
                        choices:
                            - 'connected'
                            - 'static'
                            - 'rip'
            distribute_list_in:
                aliases: ['distribute-list-in']
                type: list
                elements: str
                description: Filter incoming routes.
            distribute_route_map_in:
                aliases: ['distribute-route-map-in']
                type: list
                elements: str
                description: Filter incoming external routes by route-map.
            log_neighbour_changes:
                aliases: ['log-neighbour-changes']
                type: str
                description: Log of OSPF neighbor changes.
                choices:
                    - 'disable'
                    - 'enable'
            neighbor:
                type: list
                elements: dict
                description: Neighbor.
                suboptions:
                    cost:
                        type: int
                        description: Cost of the interface, value range from 0 to 65535, 0 means auto-cost.
                    id:
                        type: int
                        description: Neighbor entry ID.
                    ip:
                        type: str
                        description: Interface IP address of the neighbor.
                    poll_interval:
                        aliases: ['poll-interval']
                        type: int
                        description: Poll interval time in seconds.
                    priority:
                        type: int
                        description: Priority.
            network:
                type: list
                elements: dict
                description: Network.
                suboptions:
                    area:
                        type: str
                        description: Attach the network to area.
                    comments:
                        type: str
                        description: Comment.
                    id:
                        type: int
                        description: Network entry ID.
                    prefix:
                        type: list
                        elements: str
                        description: Prefix.
            ospf_interface:
                aliases: ['ospf-interface']
                type: list
                elements: dict
                description: Ospf interface.
                suboptions:
                    authentication:
                        type: str
                        description: Authentication type.
                        choices:
                            - 'none'
                            - 'text'
                            - 'md5'
                            - 'message-digest'
                    authentication_key:
                        aliases: ['authentication-key']
                        type: list
                        elements: str
                        description: Authentication key.
                    bfd:
                        type: str
                        description: Bidirectional Forwarding Detection
                        choices:
                            - 'global'
                            - 'enable'
                            - 'disable'
                    comments:
                        type: str
                        description: Comment.
                    cost:
                        type: int
                        description: Cost of the interface, value range from 0 to 65535, 0 means auto-cost.
                    database_filter_out:
                        aliases: ['database-filter-out']
                        type: str
                        description: Enable/disable control of flooding out LSAs.
                        choices:
                            - 'disable'
                            - 'enable'
                    dead_interval:
                        aliases: ['dead-interval']
                        type: int
                        description: Dead interval.
                    hello_interval:
                        aliases: ['hello-interval']
                        type: int
                        description: Hello interval.
                    hello_multiplier:
                        aliases: ['hello-multiplier']
                        type: int
                        description: Number of hello packets within dead interval.
                    interface:
                        type: list
                        elements: str
                        description: Configuration interface name.
                    ip:
                        type: str
                        description: IP address.
                    keychain:
                        type: list
                        elements: str
                        description: Message-digest key-chain name.
                    md5_keys:
                        aliases: ['md5-keys']
                        type: list
                        elements: dict
                        description: Md5 keys.
                        suboptions:
                            id:
                                type: int
                                description: Key ID
                            key_string:
                                aliases: ['key-string']
                                type: list
                                elements: str
                                description: Password for the key.
                    mtu:
                        type: int
                        description: MTU for database description packets.
                    mtu_ignore:
                        aliases: ['mtu-ignore']
                        type: str
                        description: Enable/disable ignore MTU.
                        choices:
                            - 'disable'
                            - 'enable'
                    name:
                        type: str
                        description: Interface entry name.
                    network_type:
                        aliases: ['network-type']
                        type: str
                        description: Network type.
                        choices:
                            - 'broadcast'
                            - 'non-broadcast'
                            - 'point-to-point'
                            - 'point-to-multipoint'
                            - 'point-to-multipoint-non-broadcast'
                    prefix_length:
                        aliases: ['prefix-length']
                        type: int
                        description: Prefix length.
                    priority:
                        type: int
                        description: Priority.
                    resync_timeout:
                        aliases: ['resync-timeout']
                        type: int
                        description: Graceful restart neighbor resynchronization timeout.
                    retransmit_interval:
                        aliases: ['retransmit-interval']
                        type: int
                        description: Retransmit interval.
                    status:
                        type: str
                        description: Enable/disable status.
                        choices:
                            - 'disable'
                            - 'enable'
                    transmit_delay:
                        aliases: ['transmit-delay']
                        type: int
                        description: Transmit delay.
                    md5_keychain:
                        aliases: ['md5-keychain']
                        type: list
                        elements: str
                        description: Authentication MD5 key-chain name.
                    linkdown_fast_failover:
                        aliases: ['linkdown-fast-failover']
                        type: str
                        description: Enable/disable fast link failover.
                        choices:
                            - 'disable'
                            - 'enable'
            passive_interface:
                aliases: ['passive-interface']
                type: list
                elements: str
                description: Passive interface configuration.
            redistribute:
                type: dict
                description: Redistribute.
                suboptions:
                    metric:
                        type: int
                        description: Redistribute metric setting.
                    metric_type:
                        aliases: ['metric-type']
                        type: str
                        description: Metric type.
                        choices:
                            - '2'
                            - '1'
                    name:
                        type: str
                        description: Redistribute name.
                    routemap:
                        type: list
                        elements: str
                        description: Route map name.
                    status:
                        type: str
                        description: Status.
                        choices:
                            - 'disable'
                            - 'enable'
                    tag:
                        type: int
                        description: Tag value.
            restart_mode:
                aliases: ['restart-mode']
                type: str
                description: OSPF restart mode
                choices:
                    - 'none'
                    - 'lls'
                    - 'graceful-restart'
            restart_on_topology_change:
                aliases: ['restart-on-topology-change']
                type: str
                description: Enable/disable continuing graceful restart upon topology change.
                choices:
                    - 'disable'
                    - 'enable'
            restart_period:
                aliases: ['restart-period']
                type: int
                description: Graceful restart period.
            rfc1583_compatible:
                aliases: ['rfc1583-compatible']
                type: str
                description: Enable/disable RFC1583 compatibility.
                choices:
                    - 'disable'
                    - 'enable'
            router_id:
                aliases: ['router-id']
                type: str
                description: Router ID.
            spf_timers:
                aliases: ['spf-timers']
                type: list
                elements: int
                description: SPF calculation frequency.
            summary_address:
                aliases: ['summary-address']
                type: list
                elements: dict
                description: Summary address.
                suboptions:
                    advertise:
                        type: str
                        description: Enable/disable advertise status.
                        choices:
                            - 'disable'
                            - 'enable'
                    id:
                        type: int
                        description: Summary address entry ID.
                    prefix:
                        type: list
                        elements: str
                        description: Prefix.
                    tag:
                        type: int
                        description: Tag value.
            lsa_refresh_interval:
                aliases: ['lsa-refresh-interval']
                type: int
                description: The minimal OSPF LSA update time interval
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
    - name: Configure OSPF.
      fortinet.fmgdevice.fmgd_router_ospf:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        router_ospf:
          # abr_type: <value in [cisco, ibm, shortcut, ...]>
          # area:
          #   - authentication: <value in [none, text, md5, ...]>
          #     comments: <string>
          #     default_cost: <integer>
          #     filter_list:
          #       - direction: <value in [out, in]>
          #         id: <integer>
          #         list: <list or string>
          #     id: <string>
          #     nssa_default_information_originate: <value in [disable, enable, always]>
          #     nssa_default_information_originate_metric: <integer>
          #     nssa_default_information_originate_metric_type: <value in [2, 1]>
          #     nssa_redistribution: <value in [disable, enable]>
          #     nssa_translator_role: <value in [candidate, never, always]>
          #     range:
          #       - advertise: <value in [disable, enable]>
          #         id: <integer>
          #         prefix: <list or string>
          #         substitute: <list or string>
          #         substitute_status: <value in [disable, enable]>
          #     shortcut: <value in [disable, enable, default]>
          #     stub_type: <value in [summary, no-summary]>
          #     type: <value in [regular, nssa, stub]>
          #     virtual_link:
          #       - authentication: <value in [none, text, md5, ...]>
          #         authentication_key: <list or string>
          #         dead_interval: <integer>
          #         hello_interval: <integer>
          #         keychain: <list or string>
          #         md5_keys:
          #           - id: <integer>
          #             key_string: <list or string>
          #         name: <string>
          #         peer: <string>
          #         retransmit_interval: <integer>
          #         transmit_delay: <integer>
          #         md5_keychain: <list or string>
          # auto_cost_ref_bandwidth: <integer>
          # bfd: <value in [disable, enable]>
          # database_overflow: <value in [disable, enable]>
          # database_overflow_max_lsas: <integer>
          # database_overflow_time_to_recover: <integer>
          # default_information_metric: <integer>
          # default_information_metric_type: <value in [2, 1]>
          # default_information_originate: <value in [disable, enable, always]>
          # default_information_route_map: <list or string>
          # default_metric: <integer>
          # distance: <integer>
          # distance_external: <integer>
          # distance_inter_area: <integer>
          # distance_intra_area: <integer>
          # distribute_list:
          #   - access_list: <list or string>
          #     id: <integer>
          #     protocol: <value in [connected, static, rip]>
          # distribute_list_in: <list or string>
          # distribute_route_map_in: <list or string>
          # log_neighbour_changes: <value in [disable, enable]>
          # neighbor:
          #   - cost: <integer>
          #     id: <integer>
          #     ip: <string>
          #     poll_interval: <integer>
          #     priority: <integer>
          # network:
          #   - area: <string>
          #     comments: <string>
          #     id: <integer>
          #     prefix: <list or string>
          # ospf_interface:
          #   - authentication: <value in [none, text, md5, ...]>
          #     authentication_key: <list or string>
          #     bfd: <value in [global, enable, disable]>
          #     comments: <string>
          #     cost: <integer>
          #     database_filter_out: <value in [disable, enable]>
          #     dead_interval: <integer>
          #     hello_interval: <integer>
          #     hello_multiplier: <integer>
          #     interface: <list or string>
          #     ip: <string>
          #     keychain: <list or string>
          #     md5_keys:
          #       - id: <integer>
          #         key_string: <list or string>
          #     mtu: <integer>
          #     mtu_ignore: <value in [disable, enable]>
          #     name: <string>
          #     network_type: <value in [broadcast, non-broadcast, point-to-point, ...]>
          #     prefix_length: <integer>
          #     priority: <integer>
          #     resync_timeout: <integer>
          #     retransmit_interval: <integer>
          #     status: <value in [disable, enable]>
          #     transmit_delay: <integer>
          #     md5_keychain: <list or string>
          #     linkdown_fast_failover: <value in [disable, enable]>
          # passive_interface: <list or string>
          # redistribute:
          #   metric: <integer>
          #   metric_type: <value in [2, 1]>
          #   name: <string>
          #   routemap: <list or string>
          #   status: <value in [disable, enable]>
          #   tag: <integer>
          # restart_mode: <value in [none, lls, graceful-restart]>
          # restart_on_topology_change: <value in [disable, enable]>
          # restart_period: <integer>
          # rfc1583_compatible: <value in [disable, enable]>
          # router_id: <string>
          # spf_timers: <list or integer>
          # summary_address:
          #   - advertise: <value in [disable, enable]>
          #     id: <integer>
          #     prefix: <list or string>
          #     tag: <integer>
          # lsa_refresh_interval: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/ospf'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'router_ospf': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'abr-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['cisco', 'ibm', 'shortcut', 'standard'], 'type': 'str'},
                'area': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'authentication': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['none', 'text', 'md5', 'message-digest'],
                            'type': 'str'
                        },
                        'comments': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'default-cost': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'filter-list': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'direction': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['out', 'in'], 'type': 'str'},
                                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'nssa-default-information-originate': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['disable', 'enable', 'always'],
                            'type': 'str'
                        },
                        'nssa-default-information-originate-metric': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'nssa-default-information-originate-metric-type': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['2', '1'],
                            'type': 'str'
                        },
                        'nssa-redistribution': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'nssa-translator-role': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['candidate', 'never', 'always'],
                            'type': 'str'
                        },
                        'range': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'advertise': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'prefix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                                'substitute': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                                'substitute-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'shortcut': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'default'], 'type': 'str'},
                        'stub-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['summary', 'no-summary'], 'type': 'str'},
                        'type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['regular', 'nssa', 'stub'], 'type': 'str'},
                        'virtual-link': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'authentication': {
                                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                                    'choices': ['none', 'text', 'md5', 'message-digest'],
                                    'type': 'str'
                                },
                                'authentication-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                                'dead-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'hello-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'keychain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                                'md5-keys': {
                                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                                    'no_log': True,
                                    'type': 'list',
                                    'options': {
                                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                        'key-string': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'}
                                    },
                                    'elements': 'dict'
                                },
                                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                                'peer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                                'retransmit-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'transmit-delay': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'md5-keychain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'}
                            },
                            'elements': 'dict'
                        }
                    },
                    'elements': 'dict'
                },
                'auto-cost-ref-bandwidth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'bfd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'database-overflow': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'database-overflow-max-lsas': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'database-overflow-time-to-recover': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'default-information-metric': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'default-information-metric-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['2', '1'], 'type': 'str'},
                'default-information-originate': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['disable', 'enable', 'always'],
                    'type': 'str'
                },
                'default-information-route-map': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'default-metric': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'distance': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'distance-external': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'distance-inter-area': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'distance-intra-area': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'distribute-list': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'access-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'protocol': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['connected', 'static', 'rip'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'distribute-list-in': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'distribute-route-map-in': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'log-neighbour-changes': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'neighbor': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'cost': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'poll-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'network': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'area': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'comments': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'prefix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'ospf-interface': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'authentication': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['none', 'text', 'md5', 'message-digest'],
                            'type': 'str'
                        },
                        'authentication-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'bfd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['global', 'enable', 'disable'], 'type': 'str'},
                        'comments': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'cost': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'database-filter-out': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dead-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'hello-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'hello-multiplier': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'keychain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'md5-keys': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'no_log': True,
                            'type': 'list',
                            'options': {
                                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'key-string': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'mtu': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'mtu-ignore': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'network-type': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['broadcast', 'non-broadcast', 'point-to-point', 'point-to-multipoint', 'point-to-multipoint-non-broadcast'],
                            'type': 'str'
                        },
                        'prefix-length': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'resync-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'retransmit-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'transmit-delay': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'md5-keychain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'linkdown-fast-failover': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'passive-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'redistribute': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'metric': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'metric-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['2', '1'], 'type': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'routemap': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    }
                },
                'restart-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'lls', 'graceful-restart'], 'type': 'str'},
                'restart-on-topology-change': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'restart-period': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'rfc1583-compatible': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'router-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'spf-timers': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'summary-address': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'advertise': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'prefix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'tag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'lsa-refresh-interval': {'v_range': [['7.6.0', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_ospf'),
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
