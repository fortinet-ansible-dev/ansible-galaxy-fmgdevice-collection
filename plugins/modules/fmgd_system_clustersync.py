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
module: fmgd_system_clustersync
short_description: Device system cluster sync
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
    system_clustersync:
        description: The top level parameters set.
        required: false
        type: dict
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
            ike_heartbeat_interval:
                aliases: ['ike-heartbeat-interval']
                type: int
                description: IKE heartbeat interval
            ike_monitor:
                aliases: ['ike-monitor']
                type: str
                description: Enable/disable IKE HA monitor.
                choices:
                    - 'disable'
                    - 'enable'
            ike_monitor_interval:
                aliases: ['ike-monitor-interval']
                type: int
                description: IKE HA monitor interval
            ike_use_rfc6311:
                aliases: ['ike-use-rfc6311']
                type: str
                description: Enable/disable RFC6311 option.
                choices:
                    - 'disable'
                    - 'enable'
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
                        type: str
                        description: Only sessions from this interface are synchronized.
            sync_id:
                aliases: ['sync-id']
                type: int
                description: Sync ID.
            syncvd:
                type: list
                elements: str
                description: Sessions from these VDOMs are synchronized using this session synchronization configuration.
            ike_seqjump_speed:
                aliases: ['ike-seqjump-speed']
                type: int
                description: Ike seqjump speed.
            slave_add_ike_routes:
                aliases: ['slave-add-ike-routes']
                type: str
                description: Enable/disable IKE route announcement on the backup unit.
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
    - name: Device system cluster sync
      fortinet.fmgdevice.fmgd_system_clustersync:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        state: present # <value in [present, absent]>
        system_clustersync:
          # down_intfs_before_sess_sync: <list or string>
          # hb_interval: <integer>
          # hb_lost_threshold: <integer>
          # ike_heartbeat_interval: <integer>
          # ike_monitor: <value in [disable, enable]>
          # ike_monitor_interval: <integer>
          # ike_use_rfc6311: <value in [disable, enable]>
          # ipsec_tunnel_sync: <value in [disable, enable]>
          # peerip: <string>
          # peervd: <list or string>
          # secondary_add_ipsec_routes: <value in [disable, enable]>
          # session_sync_filter:
          #   custom_service:
          #     - dst_port_range: <string>
          #       id: <integer>
          #       src_port_range: <string>
          #   dstaddr: <list or string>
          #   dstaddr6: <string>
          #   dstintf: <list or string>
          #   srcaddr: <list or string>
          #   srcaddr6: <string>
          #   srcintf: <string>
          # sync_id: <integer>
          # syncvd: <list or string>
          # ike_seqjump_speed: <integer>
          # slave_add_ike_routes: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/system/cluster-sync'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_clustersync': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'down-intfs-before-sess-sync': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'hb-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'hb-lost-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ike-heartbeat-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ike-monitor': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ike-monitor-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ike-use-rfc6311': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
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
                        'srcintf': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    }
                },
                'sync-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'syncvd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ike-seqjump-speed': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'slave-add-ike-routes': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_clustersync'),
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
