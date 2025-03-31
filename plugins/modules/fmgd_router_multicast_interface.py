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
module: fmgd_router_multicast_interface
short_description: PIM interfaces.
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
    router_multicast_interface:
        description: The top level parameters set.
        required: false
        type: dict
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
                required: true
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
    - name: PIM interfaces.
      fortinet.fmgdevice.fmgd_router_multicast_interface:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        router_multicast_interface:
          name: "your value" # Required variable, string
          # bfd: <value in [disable, enable]>
          # cisco_exclude_genid: <value in [disable, enable]>
          # dr_priority: <integer>
          # hello_holdtime: <integer>
          # hello_interval: <integer>
          # igmp:
          #   access_group: <list or string>
          #   immediate_leave_group: <list or string>
          #   last_member_query_count: <integer>
          #   last_member_query_interval: <integer>
          #   query_interval: <integer>
          #   query_max_response_time: <integer>
          #   query_timeout: <integer>
          #   router_alert_check: <value in [disable, enable]>
          #   version: <value in [1, 2, 3]>
          # join_group:
          #   - address: <string>
          # multicast_flow: <list or string>
          # neighbour_filter: <list or string>
          # passive: <value in [disable, enable]>
          # pim_mode: <value in [sparse-mode, dense-mode]>
          # propagation_delay: <integer>
          # rp_candidate: <value in [disable, enable]>
          # rp_candidate_group: <list or string>
          # rp_candidate_interval: <integer>
          # rp_candidate_priority: <integer>
          # rpf_nbr_fail_back: <value in [disable, enable]>
          # rpf_nbr_fail_back_filter: <list or string>
          # state_refresh_interval: <integer>
          # static_group: <list or string>
          # ttl_threshold: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/multicast/interface'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'router_multicast_interface': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
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
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
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
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_multicast_interface'),
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
