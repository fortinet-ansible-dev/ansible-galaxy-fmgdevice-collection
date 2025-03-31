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
module: fmgd_router_multicast_pimsmglobal
short_description: PIM sparse-mode global settings.
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
    router_multicast_pimsmglobal:
        description: The top level parameters set.
        required: false
        type: dict
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
    - name: PIM sparse-mode global settings.
      fortinet.fmgdevice.fmgd_router_multicast_pimsmglobal:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        router_multicast_pimsmglobal:
          # accept_register_list: <list or string>
          # accept_source_list: <list or string>
          # bsr_allow_quick_refresh: <value in [disable, enable]>
          # bsr_candidate: <value in [disable, enable]>
          # bsr_hash: <integer>
          # bsr_interface: <list or string>
          # bsr_priority: <integer>
          # cisco_crp_prefix: <value in [disable, enable]>
          # cisco_ignore_rp_set_priority: <value in [disable, enable]>
          # cisco_register_checksum: <value in [disable, enable]>
          # cisco_register_checksum_group: <list or string>
          # join_prune_holdtime: <integer>
          # message_interval: <integer>
          # null_register_retries: <integer>
          # pim_use_sdwan: <value in [disable, enable]>
          # register_rate_limit: <integer>
          # register_rp_reachability: <value in [disable, enable]>
          # register_source: <value in [disable, ip-address, interface]>
          # register_source_interface: <list or string>
          # register_source_ip: <string>
          # register_supression: <integer>
          # rp_address:
          #   - group: <list or string>
          #     id: <integer>
          #     ip_address: <string>
          # rp_register_keepalive: <integer>
          # spt_threshold: <value in [disable, enable]>
          # spt_threshold_group: <list or string>
          # ssm: <value in [disable, enable]>
          # ssm_range: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/multicast/pim-sm-global'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'router_multicast_pimsmglobal': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
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
                'register-source': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'ip-address', 'interface'], 'type': 'str'},
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
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_multicast_pimsmglobal'),
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
