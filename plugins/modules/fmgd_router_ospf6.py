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
module: fmgd_router_ospf6
short_description: Configure IPv6 OSPF.
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
    router_ospf6:
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
                    - 'standard'
            area:
                type: list
                elements: dict
                description: Area.
                suboptions:
                    authentication:
                        type: str
                        description: Authentication mode.
                        choices:
                            - 'none'
                            - 'ah'
                            - 'esp'
                    default_cost:
                        aliases: ['default-cost']
                        type: int
                        description: Summary default cost of stub or NSSA area.
                    id:
                        type: str
                        description: Area entry IP address.
                    ipsec_auth_alg:
                        aliases: ['ipsec-auth-alg']
                        type: str
                        description: Authentication algorithm.
                        choices:
                            - 'md5'
                            - 'sha1'
                            - 'sha256'
                            - 'sha384'
                            - 'sha512'
                    ipsec_enc_alg:
                        aliases: ['ipsec-enc-alg']
                        type: str
                        description: Encryption algorithm.
                        choices:
                            - 'null'
                            - 'des'
                            - '3des'
                            - 'aes128'
                            - 'aes192'
                            - 'aes256'
                    ipsec_keys:
                        aliases: ['ipsec-keys']
                        type: list
                        elements: dict
                        description: Ipsec keys.
                        suboptions:
                            auth_key:
                                aliases: ['auth-key']
                                type: list
                                elements: str
                                description: Authentication key.
                            enc_key:
                                aliases: ['enc-key']
                                type: list
                                elements: str
                                description: Encryption key.
                            spi:
                                type: int
                                description: Security Parameters Index.
                    key_rollover_interval:
                        aliases: ['key-rollover-interval']
                        type: int
                        description: Key roll-over interval.
                    nssa_default_information_originate:
                        aliases: ['nssa-default-information-originate']
                        type: str
                        description: Enable/disable originate type 7 default into NSSA area.
                        choices:
                            - 'disable'
                            - 'enable'
                    nssa_default_information_originate_metric:
                        aliases: ['nssa-default-information-originate-metric']
                        type: int
                        description: OSPFv3 default metric.
                    nssa_default_information_originate_metric_type:
                        aliases: ['nssa-default-information-originate-metric-type']
                        type: str
                        description: OSPFv3 metric type for default routes.
                        choices:
                            - '1'
                            - '2'
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
                            prefix6:
                                type: str
                                description: IPv6 prefix.
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
                                description: Authentication mode.
                                choices:
                                    - 'none'
                                    - 'ah'
                                    - 'esp'
                                    - 'area'
                            dead_interval:
                                aliases: ['dead-interval']
                                type: int
                                description: Dead interval.
                            hello_interval:
                                aliases: ['hello-interval']
                                type: int
                                description: Hello interval.
                            ipsec_auth_alg:
                                aliases: ['ipsec-auth-alg']
                                type: str
                                description: Authentication algorithm.
                                choices:
                                    - 'md5'
                                    - 'sha1'
                                    - 'sha256'
                                    - 'sha384'
                                    - 'sha512'
                            ipsec_enc_alg:
                                aliases: ['ipsec-enc-alg']
                                type: str
                                description: Encryption algorithm.
                                choices:
                                    - 'null'
                                    - 'des'
                                    - '3des'
                                    - 'aes128'
                                    - 'aes192'
                                    - 'aes256'
                            ipsec_keys:
                                aliases: ['ipsec-keys']
                                type: list
                                elements: dict
                                description: Ipsec keys.
                                suboptions:
                                    auth_key:
                                        aliases: ['auth-key']
                                        type: list
                                        elements: str
                                        description: Authentication key.
                                    enc_key:
                                        aliases: ['enc-key']
                                        type: list
                                        elements: str
                                        description: Encryption key.
                                    spi:
                                        type: int
                                        description: Security Parameters Index.
                            key_rollover_interval:
                                aliases: ['key-rollover-interval']
                                type: int
                                description: Key roll-over interval.
                            name:
                                type: str
                                description: Virtual link entry name.
                            peer:
                                type: str
                                description: A.
                            retransmit_interval:
                                aliases: ['retransmit-interval']
                                type: int
                                description: Retransmit interval.
                            transmit_delay:
                                aliases: ['transmit-delay']
                                type: int
                                description: Transmit delay.
            auto_cost_ref_bandwidth:
                aliases: ['auto-cost-ref-bandwidth']
                type: int
                description: Reference bandwidth in terms of megabits per second.
            bfd:
                type: str
                description: Enable/disable Bidirectional Forwarding Detection
                choices:
                    - 'disable'
                    - 'enable'
            default_information_metric:
                aliases: ['default-information-metric']
                type: int
                description: Default information metric.
            default_information_metric_type:
                aliases: ['default-information-metric-type']
                type: str
                description: Default information metric type.
                choices:
                    - '1'
                    - '2'
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
            log_neighbour_changes:
                aliases: ['log-neighbour-changes']
                type: str
                description: Log OSPFv3 neighbor changes.
                choices:
                    - 'disable'
                    - 'enable'
            ospf6_interface:
                aliases: ['ospf6-interface']
                type: list
                elements: dict
                description: Ospf6 interface.
                suboptions:
                    area_id:
                        aliases: ['area-id']
                        type: str
                        description: A.
                    authentication:
                        type: str
                        description: Authentication mode.
                        choices:
                            - 'none'
                            - 'ah'
                            - 'esp'
                            - 'area'
                    bfd:
                        type: str
                        description: Enable/disable Bidirectional Forwarding Detection
                        choices:
                            - 'global'
                            - 'enable'
                            - 'disable'
                    cost:
                        type: int
                        description: Cost of the interface, value range from 0 to 65535, 0 means auto-cost.
                    dead_interval:
                        aliases: ['dead-interval']
                        type: int
                        description: Dead interval.
                    hello_interval:
                        aliases: ['hello-interval']
                        type: int
                        description: Hello interval.
                    interface:
                        type: list
                        elements: str
                        description: Configuration interface name.
                    ipsec_auth_alg:
                        aliases: ['ipsec-auth-alg']
                        type: str
                        description: Authentication algorithm.
                        choices:
                            - 'md5'
                            - 'sha1'
                            - 'sha256'
                            - 'sha384'
                            - 'sha512'
                    ipsec_enc_alg:
                        aliases: ['ipsec-enc-alg']
                        type: str
                        description: Encryption algorithm.
                        choices:
                            - 'null'
                            - 'des'
                            - '3des'
                            - 'aes128'
                            - 'aes192'
                            - 'aes256'
                    ipsec_keys:
                        aliases: ['ipsec-keys']
                        type: list
                        elements: dict
                        description: Ipsec keys.
                        suboptions:
                            auth_key:
                                aliases: ['auth-key']
                                type: list
                                elements: str
                                description: Authentication key.
                            enc_key:
                                aliases: ['enc-key']
                                type: list
                                elements: str
                                description: Encryption key.
                            spi:
                                type: int
                                description: Security Parameters Index.
                    key_rollover_interval:
                        aliases: ['key-rollover-interval']
                        type: int
                        description: Key roll-over interval.
                    mtu:
                        type: int
                        description: MTU for OSPFv3 packets.
                    mtu_ignore:
                        aliases: ['mtu-ignore']
                        type: str
                        description: Enable/disable ignoring MTU field in DBD packets.
                        choices:
                            - 'disable'
                            - 'enable'
                    name:
                        type: str
                        description: Interface entry name.
                    neighbor:
                        type: list
                        elements: dict
                        description: Neighbor.
                        suboptions:
                            cost:
                                type: int
                                description: Cost of the interface, value range from 0 to 65535, 0 means auto-cost.
                            ip6:
                                type: str
                                description: IPv6 link local address of the neighbor.
                            poll_interval:
                                aliases: ['poll-interval']
                                type: int
                                description: Poll interval time in seconds.
                            priority:
                                type: int
                                description: Priority.
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
                    priority:
                        type: int
                        description: Priority.
                    retransmit_interval:
                        aliases: ['retransmit-interval']
                        type: int
                        description: Retransmit interval.
                    status:
                        type: str
                        description: Enable/disable OSPF6 routing on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    transmit_delay:
                        aliases: ['transmit-delay']
                        type: int
                        description: Transmit delay.
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
                            - '1'
                            - '2'
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
            restart_mode:
                aliases: ['restart-mode']
                type: str
                description: OSPFv3 restart mode
                choices:
                    - 'none'
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
                description: Graceful restart period in seconds.
            router_id:
                aliases: ['router-id']
                type: str
                description: A.
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
                    prefix6:
                        type: str
                        description: IPv6 prefix.
                    tag:
                        type: int
                        description: Tag value.
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
    - name: Configure IPv6 OSPF.
      fortinet.fmgdevice.fmgd_router_ospf6:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        router_ospf6:
          # abr_type: <value in [cisco, ibm, standard]>
          # area:
          #   - authentication: <value in [none, ah, esp]>
          #     default_cost: <integer>
          #     id: <string>
          #     ipsec_auth_alg: <value in [md5, sha1, sha256, ...]>
          #     ipsec_enc_alg: <value in [null, des, 3des, ...]>
          #     ipsec_keys:
          #       - auth_key: <list or string>
          #         enc_key: <list or string>
          #         spi: <integer>
          #     key_rollover_interval: <integer>
          #     nssa_default_information_originate: <value in [disable, enable]>
          #     nssa_default_information_originate_metric: <integer>
          #     nssa_default_information_originate_metric_type: <value in [1, 2]>
          #     nssa_redistribution: <value in [disable, enable]>
          #     nssa_translator_role: <value in [candidate, never, always]>
          #     range:
          #       - advertise: <value in [disable, enable]>
          #         id: <integer>
          #         prefix6: <string>
          #     stub_type: <value in [summary, no-summary]>
          #     type: <value in [regular, nssa, stub]>
          #     virtual_link:
          #       - authentication: <value in [none, ah, esp, ...]>
          #         dead_interval: <integer>
          #         hello_interval: <integer>
          #         ipsec_auth_alg: <value in [md5, sha1, sha256, ...]>
          #         ipsec_enc_alg: <value in [null, des, 3des, ...]>
          #         ipsec_keys:
          #           - auth_key: <list or string>
          #             enc_key: <list or string>
          #             spi: <integer>
          #         key_rollover_interval: <integer>
          #         name: <string>
          #         peer: <string>
          #         retransmit_interval: <integer>
          #         transmit_delay: <integer>
          # auto_cost_ref_bandwidth: <integer>
          # bfd: <value in [disable, enable]>
          # default_information_metric: <integer>
          # default_information_metric_type: <value in [1, 2]>
          # default_information_originate: <value in [disable, enable, always]>
          # default_information_route_map: <list or string>
          # default_metric: <integer>
          # log_neighbour_changes: <value in [disable, enable]>
          # ospf6_interface:
          #   - area_id: <string>
          #     authentication: <value in [none, ah, esp, ...]>
          #     bfd: <value in [global, enable, disable]>
          #     cost: <integer>
          #     dead_interval: <integer>
          #     hello_interval: <integer>
          #     interface: <list or string>
          #     ipsec_auth_alg: <value in [md5, sha1, sha256, ...]>
          #     ipsec_enc_alg: <value in [null, des, 3des, ...]>
          #     ipsec_keys:
          #       - auth_key: <list or string>
          #         enc_key: <list or string>
          #         spi: <integer>
          #     key_rollover_interval: <integer>
          #     mtu: <integer>
          #     mtu_ignore: <value in [disable, enable]>
          #     name: <string>
          #     neighbor:
          #       - cost: <integer>
          #         ip6: <string>
          #         poll_interval: <integer>
          #         priority: <integer>
          #     network_type: <value in [broadcast, non-broadcast, point-to-point, ...]>
          #     priority: <integer>
          #     retransmit_interval: <integer>
          #     status: <value in [disable, enable]>
          #     transmit_delay: <integer>
          # passive_interface: <list or string>
          # redistribute:
          #   metric: <integer>
          #   metric_type: <value in [1, 2]>
          #   name: <string>
          #   routemap: <list or string>
          #   status: <value in [disable, enable]>
          # restart_mode: <value in [none, graceful-restart]>
          # restart_on_topology_change: <value in [disable, enable]>
          # restart_period: <integer>
          # router_id: <string>
          # spf_timers: <list or integer>
          # summary_address:
          #   - advertise: <value in [disable, enable]>
          #     id: <integer>
          #     prefix6: <string>
          #     tag: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/ospf6'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'router_ospf6': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'abr-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['cisco', 'ibm', 'standard'], 'type': 'str'},
                'area': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'authentication': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'ah', 'esp'], 'type': 'str'},
                        'default-cost': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'ipsec-auth-alg': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['md5', 'sha1', 'sha256', 'sha384', 'sha512'],
                            'type': 'str'
                        },
                        'ipsec-enc-alg': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['null', 'des', '3des', 'aes128', 'aes192', 'aes256'],
                            'type': 'str'
                        },
                        'ipsec-keys': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'no_log': True,
                            'type': 'list',
                            'options': {
                                'auth-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                                'enc-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                                'spi': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'key-rollover-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                        'nssa-default-information-originate': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'nssa-default-information-originate-metric': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'nssa-default-information-originate-metric-type': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['1', '2'],
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
                                'prefix6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'stub-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['summary', 'no-summary'], 'type': 'str'},
                        'type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['regular', 'nssa', 'stub'], 'type': 'str'},
                        'virtual-link': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'authentication': {
                                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                                    'choices': ['none', 'ah', 'esp', 'area'],
                                    'type': 'str'
                                },
                                'dead-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'hello-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'ipsec-auth-alg': {
                                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                                    'choices': ['md5', 'sha1', 'sha256', 'sha384', 'sha512'],
                                    'type': 'str'
                                },
                                'ipsec-enc-alg': {
                                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                                    'choices': ['null', 'des', '3des', 'aes128', 'aes192', 'aes256'],
                                    'type': 'str'
                                },
                                'ipsec-keys': {
                                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                                    'no_log': True,
                                    'type': 'list',
                                    'options': {
                                        'auth-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                                        'enc-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                                        'spi': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                                    },
                                    'elements': 'dict'
                                },
                                'key-rollover-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                                'peer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                                'retransmit-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'transmit-delay': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        }
                    },
                    'elements': 'dict'
                },
                'auto-cost-ref-bandwidth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'bfd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'default-information-metric': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'default-information-metric-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['1', '2'], 'type': 'str'},
                'default-information-originate': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['disable', 'enable', 'always'],
                    'type': 'str'
                },
                'default-information-route-map': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'default-metric': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'log-neighbour-changes': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ospf6-interface': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'area-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'authentication': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'ah', 'esp', 'area'], 'type': 'str'},
                        'bfd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['global', 'enable', 'disable'], 'type': 'str'},
                        'cost': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'dead-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'hello-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'ipsec-auth-alg': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['md5', 'sha1', 'sha256', 'sha384', 'sha512'],
                            'type': 'str'
                        },
                        'ipsec-enc-alg': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['null', 'des', '3des', 'aes128', 'aes192', 'aes256'],
                            'type': 'str'
                        },
                        'ipsec-keys': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'no_log': True,
                            'type': 'list',
                            'options': {
                                'auth-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                                'enc-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                                'spi': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'key-rollover-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                        'mtu': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'mtu-ignore': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'neighbor': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'cost': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'ip6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                                'poll-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'network-type': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['broadcast', 'non-broadcast', 'point-to-point', 'point-to-multipoint', 'point-to-multipoint-non-broadcast'],
                            'type': 'str'
                        },
                        'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'retransmit-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'transmit-delay': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'passive-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'redistribute': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'metric': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'metric-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['1', '2'], 'type': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'routemap': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'restart-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'graceful-restart'], 'type': 'str'},
                'restart-on-topology-change': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'restart-period': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'router-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'spf-timers': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'summary-address': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'advertise': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'prefix6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'tag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_ospf6'),
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
