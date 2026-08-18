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
module: fmgd_system_sdwan_members
short_description: FortiGate interfaces added to the SD-WAN.
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
  system_sdwan_members:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      comment:
        type: str
        description: Comments.
      cost:
        type: int
        description:
          - Support meta variable
          - Cost of this interface for services in SLA mode
      gateway:
        type: str
        description:
          - Support meta variable
          - The default gateway for this interface.
      gateway6:
        type: str
        description:
          - Support meta variable
          - IPv6 gateway.
      ingress_spillover_threshold:
        aliases: ['ingress-spillover-threshold']
        type: int
        description:
          - Support meta variable
          - Ingress spillover threshold for this interface
      interface:
        type: list
        elements: str
        description:
          - Support meta variable
          - Interface name.
      preferred_source:
        aliases: ['preferred-source']
        type: str
        description: Preferred source of route for this member.
      priority:
        type: int
        description:
          - Support meta variable
          - Priority of the interface for IPv4
      priority6:
        type: int
        description:
          - Support meta variable
          - Priority of the interface for IPv6
      seq_num:
        aliases: ['seq-num']
        type: int
        description: Sequence number
      source:
        type: str
        description:
          - Support meta variable
          - Source IP address used in the health-check packet to the server.
      source6:
        type: str
        description:
          - Support meta variable
          - Source IPv6 address used in the health-check packet to the server.
      spillover_threshold:
        aliases: ['spillover-threshold']
        type: int
        description:
          - Support meta variable
          - Egress spillover threshold for this interface
      status:
        type: str
        description: Enable/disable this interface in the SD-WAN.
        choices: ['disable', 'enable']
      transport_group:
        aliases: ['transport-group']
        type: int
        description: Measured transport group
      volume_ratio:
        aliases: ['volume-ratio']
        type: int
        description:
          - Support meta variable
          - Measured volume ratio
      weight:
        type: int
        description:
          - Support meta variable
          - Weight of this interface for weighted load balancing.
      zone:
        type: list
        elements: str
        description: Zone name.
      priority_in_sla:
        aliases: ['priority-in-sla']
        type: int
        description: Preferred priority of routes to this member when this member is in-sla
      priority_out_sla:
        aliases: ['priority-out-sla']
        type: int
        description: Preferred priority of routes to this member when this member is out-of-sla
      billing_start_day:
        aliases: ['billing-start-day']
        type: int
        description: Volume billing start day when this members volume usgage will begin to calculate.
      duplication_threshold_bandwidth:
        aliases: ['duplication-threshold-bandwidth']
        type: str
        description: Configure duplication threshold bandwidth interface in the SD-WAN.
        choices: ['overlay', 'underlay']
      duplication_threshold_bibandwidth:
        aliases: ['duplication-threshold-bibandwidth']
        type: int
        description: Bandwidth bistream threshold value in kilobytes per second
      duplication_threshold_dwbandwidth:
        aliases: ['duplication-threshold-dwbandwidth']
        type: int
        description: Bandwidth downstream threshold value in kilobytes per second
      duplication_threshold_upbandwidth:
        aliases: ['duplication-threshold-upbandwidth']
        type: int
        description: Bandwidth upstream threshold value in kilobytes per second
      overage:
        type: str
        description: Enable/disable the volume overage when members volume usage reaches quota-limit.
        choices: ['disable', 'enable']
      overage_cost:
        aliases: ['overage-cost']
        type: int
        description: Cost value for this member when its volume is over quota and overage is enabled
      overage_volume_ratio:
        aliases: ['overage-volume-ratio']
        type: int
        description: Volume ratio value for this member when its volume is over quota and overage is enabled
      overage_weight:
        aliases: ['overage-weight']
        type: int
        description: Weight value for this member when its volume is over quota and overage is enabled.
      quota_limit:
        aliases: ['quota-limit']
        type: int
        description: Volume quota limit assigned to this member in gigabytes
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: FortiGate interfaces added to the SD-WAN.
      fortinet.fmgdevice.fmgd_system_sdwan_members:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        system_sdwan_members:
          # comment: <string>
          # cost: <integer>
          # gateway: <string>
          # gateway6: <string>
          # ingress_spillover_threshold: <integer>
          # interface: <list or string>
          # preferred_source: <string>
          # priority: <integer>
          # priority6: <integer>
          # seq_num: <integer>
          # source: <string>
          # source6: <string>
          # spillover_threshold: <integer>
          # status: <value in [disable, enable]>
          # transport_group: <integer>
          # volume_ratio: <integer>
          # weight: <integer>
          # zone: <list or string>
          # priority_in_sla: <integer>
          # priority_out_sla: <integer>
          # billing_start_day: <integer>
          # duplication_threshold_bandwidth: <value in [overlay, underlay]>
          # duplication_threshold_bibandwidth: <integer>
          # duplication_threshold_dwbandwidth: <integer>
          # duplication_threshold_upbandwidth: <integer>
          # overage: <value in [disable, enable]>
          # overage_cost: <integer>
          # overage_volume_ratio: <integer>
          # overage_weight: <integer>
          # quota_limit: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/members'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_sdwan_members': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'comment': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'cost': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'gateway': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'gateway6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'ingress-spillover-threshold': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'preferred-source': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'priority6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'seq-num': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'source': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'source6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'spillover-threshold': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'transport-group': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'volume-ratio': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'weight': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'zone': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'priority-in-sla': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'priority-out-sla': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'billing-start-day': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'duplication-threshold-bandwidth': {'v_range': [['8.0.0', '']], 'choices': ['overlay', 'underlay'], 'type': 'str'},
                'duplication-threshold-bibandwidth': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'duplication-threshold-dwbandwidth': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'duplication-threshold-upbandwidth': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'overage': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'overage-cost': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'overage-volume-ratio': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'overage-weight': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'quota-limit': {'v_range': [['8.0.0', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_sdwan_members'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
