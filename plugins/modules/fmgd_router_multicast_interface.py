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
  router_multicast_interface:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      bfd:
        type: str
        description: Enable/disable Protocol Independent Multicast
        choices: ['disable', 'enable']
      cisco_exclude_genid:
        aliases: ['cisco-exclude-genid']
        type: str
        description: Exclude GenID from hello packets
        choices: ['disable', 'enable']
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
            choices: ['disable', 'enable']
          version:
            type: str
            description: Maximum version of IGMP to support.
            choices: ['1', '2', '3']
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
        choices: ['disable', 'enable']
      pim_mode:
        aliases: ['pim-mode']
        type: str
        description: PIM operation mode.
        choices: ['sparse-mode', 'dense-mode']
      propagation_delay:
        aliases: ['propagation-delay']
        type: int
        description: Delay flooding packets on this interface
      rp_candidate:
        aliases: ['rp-candidate']
        type: str
        description: Enable/disable compete to become RP in elections.
        choices: ['disable', 'enable']
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
        choices: ['disable', 'enable']
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
      update_source:
        aliases: ['update-source']
        type: list
        elements: str
        description: Interface to use as source IP.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: PIM interfaces.
      fortinet.fmgdevice.fmgd_router_multicast_interface:
        # workspace_locking_adom: <global or your adom name>
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
          # update_source: <list or string>
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
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'router_multicast_interface': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'bfd': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cisco-exclude-genid': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dr-priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'hello-holdtime': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'hello-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'igmp': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'access-group': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'immediate-leave-group': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'last-member-query-count': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'last-member-query-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'query-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'query-max-response-time': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'query-timeout': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'router-alert-check': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'version': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['1', '2', '3'], 'type': 'str'}
                    }
                },
                'join-group': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {'address': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'multicast-flow': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'neighbour-filter': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'passive': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pim-mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['sparse-mode', 'dense-mode'], 'type': 'str'},
                'propagation-delay': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'rp-candidate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rp-candidate-group': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'rp-candidate-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'rp-candidate-priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'rpf-nbr-fail-back': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rpf-nbr-fail-back-filter': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'state-refresh-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'static-group': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ttl-threshold': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'update-source': {'v_range': [['7.6.7', '7.6.7']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_multicast_interface'),
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
