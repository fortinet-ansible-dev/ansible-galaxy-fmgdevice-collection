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
module: fmgd_system_standalonecluster
short_description: Configure FortiGate Session Life Support Protocol
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
    system_standalonecluster:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            asymmetric_traffic_control:
                aliases: ['asymmetric-traffic-control']
                type: str
                description: Asymmetric traffic control mode.
                choices:
                    - 'cps-preferred'
                    - 'strict-anti-replay'
            cluster_peer:
                aliases: ['cluster-peer']
                type: list
                elements: dict
                description: Cluster peer.
                suboptions:
                    down_intfs_before_sess_sync:
                        aliases: ['down-intfs-before-sess-sync']
                        type: list
                        elements: str
                        description: List of interfaces to be turned down before session synchronization is complete.
                    hb_interval:
                        aliases: ['hb-interval']
                        type: int
                        description: Heartbeat interval
                    hb_lost_threshold:
                        aliases: ['hb-lost-threshold']
                        type: int
                        description: Lost heartbeat threshold
                    ipsec_tunnel_sync:
                        aliases: ['ipsec-tunnel-sync']
                        type: str
                        description: Enable/disable IPsec tunnel synchronization.
                        choices:
                            - 'disable'
                            - 'enable'
                    peerip:
                        type: str
                        description: IP address of the interface on the peer unit that is used for the session synchronization link.
                    peervd:
                        type: list
                        elements: str
                        description: VDOM that contains the session synchronization link interface on the peer unit.
                    secondary_add_ipsec_routes:
                        aliases: ['secondary-add-ipsec-routes']
                        type: str
                        description: Enable/disable IKE route announcement on the backup unit.
                        choices:
                            - 'disable'
                            - 'enable'
                    session_sync_filter:
                        aliases: ['session-sync-filter']
                        type: dict
                        description: Session sync filter.
                        suboptions:
                            custom_service:
                                aliases: ['custom-service']
                                type: list
                                elements: dict
                                description: Custom service.
                                suboptions:
                                    dst_port_range:
                                        aliases: ['dst-port-range']
                                        type: str
                                        description: Custom service destination port range.
                                    id:
                                        type: int
                                        description: Custom service ID.
                                    src_port_range:
                                        aliases: ['src-port-range']
                                        type: str
                                        description: Custom service source port range.
                            dstaddr:
                                type: list
                                elements: str
                                description: Only sessions to this IPv4 address are synchronized.
                            dstaddr6:
                                type: str
                                description: Only sessions to this IPv6 address are synchronized.
                            dstintf:
                                type: list
                                elements: str
                                description: Only sessions to this interface are synchronized.
                            srcaddr:
                                type: list
                                elements: str
                                description: Only sessions from this IPv4 address are synchronized.
                            srcaddr6:
                                type: str
                                description: Only sessions from this IPv6 address are synchronized.
                            srcintf:
                                type: list
                                elements: str
                                description: Only sessions from this interface are synchronized.
                    sync_id:
                        aliases: ['sync-id']
                        type: int
                        description: Sync ID.
                    syncvd:
                        type: list
                        elements: str
                        description: Sessions from these VDOMs are synchronized using this session synchronization configuration.
                    ike_monitor:
                        aliases: ['ike-monitor']
                        type: str
                        description: Ike monitor.
                        choices:
                            - 'disable'
                            - 'enable'
                    ike_use_rfc6311:
                        aliases: ['ike-use-rfc6311']
                        type: str
                        description: Ike use rfc6311.
                        choices:
                            - 'disable'
                            - 'enable'
                    ike_heartbeat_interval:
                        aliases: ['ike-heartbeat-interval']
                        type: int
                        description: Ike heartbeat interval.
                    ike_monitor_interval:
                        aliases: ['ike-monitor-interval']
                        type: int
                        description: Ike monitor interval.
            data_intf_session_sync_dev:
                aliases: ['data-intf-session-sync-dev']
                type: str
                description: Reserve data interfaces for session sync only.
            encryption:
                type: str
                description: Enable/disable encryption when synchronizing sessions.
                choices:
                    - 'disable'
                    - 'enable'
            group_member_id:
                aliases: ['group-member-id']
                type: int
                description: Cluster member ID
            layer2_connection:
                aliases: ['layer2-connection']
                type: str
                description: Indicate whether layer 2 connections are present among FGSP members.
                choices:
                    - 'unavailable'
                    - 'available'
            psksecret:
                type: list
                elements: str
                description: Pre-shared secret for session synchronization
            session_sync_dev:
                aliases: ['session-sync-dev']
                type: list
                elements: str
                description: Offload session-sync process to kernel and sync sessions using connected interface
            standalone_group_id:
                aliases: ['standalone-group-id']
                type: int
                description: Cluster group ID
            monitor_interface:
                aliases: ['monitor-interface']
                type: list
                elements: str
                description: Configure a list of interfaces on which to monitor itself.
            pingsvr_monitor_interface:
                aliases: ['pingsvr-monitor-interface']
                type: list
                elements: str
                description: List of pingsvr monitor interface to check for remote IP monitoring.
            monitor_prefix:
                aliases: ['monitor-prefix']
                type: list
                elements: dict
                description: Monitor prefix.
                suboptions:
                    id:
                        type: int
                        description: ID.
                    prefix:
                        type: list
                        elements: str
                        description: Prefix.
                    vdom:
                        type: list
                        elements: str
                        description: VDOM name.
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
    - name: Configure FortiGate Session Life Support Protocol
      fortinet.fmgdevice.fmgd_system_standalonecluster:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        system_standalonecluster:
          # asymmetric_traffic_control: <value in [cps-preferred, strict-anti-replay]>
          # cluster_peer:
          #   - down_intfs_before_sess_sync: <list or string>
          #     hb_interval: <integer>
          #     hb_lost_threshold: <integer>
          #     ipsec_tunnel_sync: <value in [disable, enable]>
          #     peerip: <string>
          #     peervd: <list or string>
          #     secondary_add_ipsec_routes: <value in [disable, enable]>
          #     session_sync_filter:
          #       custom_service:
          #         - dst_port_range: <string>
          #           id: <integer>
          #           src_port_range: <string>
          #       dstaddr: <list or string>
          #       dstaddr6: <string>
          #       dstintf: <list or string>
          #       srcaddr: <list or string>
          #       srcaddr6: <string>
          #       srcintf: <list or string>
          #     sync_id: <integer>
          #     syncvd: <list or string>
          #     ike_monitor: <value in [disable, enable]>
          #     ike_use_rfc6311: <value in [disable, enable]>
          #     ike_heartbeat_interval: <integer>
          #     ike_monitor_interval: <integer>
          # data_intf_session_sync_dev: <string>
          # encryption: <value in [disable, enable]>
          # group_member_id: <integer>
          # layer2_connection: <value in [unavailable, available]>
          # psksecret: <list or string>
          # session_sync_dev: <list or string>
          # standalone_group_id: <integer>
          # monitor_interface: <list or string>
          # pingsvr_monitor_interface: <list or string>
          # monitor_prefix:
          #   - id: <integer>
          #     prefix: <list or string>
          #     vdom: <list or string>
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
        '/pm/config/device/{device}/global/system/standalone-cluster'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_standalonecluster': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'asymmetric-traffic-control': {'v_range': [['7.4.3', '']], 'choices': ['cps-preferred', 'strict-anti-replay'], 'type': 'str'},
                'cluster-peer': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'down-intfs-before-sess-sync': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'hb-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'hb-lost-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'ipsec-tunnel-sync': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'peerip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'peervd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'secondary-add-ipsec-routes': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'session-sync-filter': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'dict',
                            'options': {
                                'custom-service': {
                                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                                    'type': 'list',
                                    'options': {
                                        'dst-port-range': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                        'src-port-range': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                                    },
                                    'elements': 'dict'
                                },
                                'dstaddr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                                'dstaddr6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                                'dstintf': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                                'srcaddr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                                'srcaddr6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                                'srcintf': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                            }
                        },
                        'sync-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'syncvd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'ike-monitor': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ike-use-rfc6311': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ike-heartbeat-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'ike-monitor-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'data-intf-session-sync-dev': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'encryption': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'group-member-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'layer2-connection': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['unavailable', 'available'], 'type': 'str'},
                'psksecret': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'session-sync-dev': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'standalone-group-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'monitor-interface': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'},
                'pingsvr-monitor-interface': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'},
                'monitor-prefix': {
                    'v_range': [['7.6.2', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.6.2', '']], 'type': 'int'},
                        'prefix': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                        'vdom': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_standalonecluster'),
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
