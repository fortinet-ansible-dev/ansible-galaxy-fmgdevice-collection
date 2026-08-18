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
module: fmgd_system_vdomproperty
short_description: Configure VDOM property.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_vdomproperty:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      custom_service:
        aliases: ['custom-service']
        type: list
        elements: int
        description: Maximum guaranteed number of firewall custom services.
      description:
        type: str
        description: Description.
      dialup_tunnel:
        aliases: ['dialup-tunnel']
        type: list
        elements: int
        description: Maximum guaranteed number of dial-up tunnels.
      firewall_address:
        aliases: ['firewall-address']
        type: list
        elements: int
        description: Maximum guaranteed number of firewall addresses
      firewall_addrgrp:
        aliases: ['firewall-addrgrp']
        type: list
        elements: int
        description: Maximum guaranteed number of firewall address groups
      firewall_policy:
        aliases: ['firewall-policy']
        type: list
        elements: int
        description: Maximum guaranteed number of firewall policies
      ipsec_phase1:
        aliases: ['ipsec-phase1']
        type: list
        elements: int
        description: Maximum guaranteed number of VPN IPsec phase 1 tunnels.
      ipsec_phase1_interface:
        aliases: ['ipsec-phase1-interface']
        type: list
        elements: int
        description: Maximum guaranteed number of VPN IPsec phase1 interface tunnels.
      ipsec_phase2:
        aliases: ['ipsec-phase2']
        type: list
        elements: int
        description: Maximum guaranteed number of VPN IPsec phase 2 tunnels.
      ipsec_phase2_interface:
        aliases: ['ipsec-phase2-interface']
        type: list
        elements: int
        description: Maximum guaranteed number of VPN IPsec phase2 interface tunnels.
      log_disk_quota:
        aliases: ['log-disk-quota']
        type: list
        elements: int
        description: Log disk quota in megabytes
      name:
        type: str
        description: VDOM name.
        required: true
      onetime_schedule:
        aliases: ['onetime-schedule']
        type: list
        elements: int
        description: Maximum guaranteed number of firewall one-time schedules.
      proxy:
        type: list
        elements: int
        description: Maximum guaranteed number of concurrent proxy users.
      recurring_schedule:
        aliases: ['recurring-schedule']
        type: list
        elements: int
        description: Maximum guaranteed number of firewall recurring schedules.
      service_group:
        aliases: ['service-group']
        type: list
        elements: int
        description: Maximum guaranteed number of firewall service groups.
      session:
        type: list
        elements: int
        description: Maximum guaranteed number of sessions.
      snmp_index:
        aliases: ['snmp-index']
        type: int
        description: Permanent SNMP Index of the virtual domain
      sslvpn:
        type: list
        elements: int
        description: Maximum guaranteed number of SSL-VPNs.
      user:
        type: list
        elements: int
        description: Maximum guaranteed number of local users.
      user_group:
        aliases: ['user-group']
        type: list
        elements: int
        description: Maximum guaranteed number of user groups.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure VDOM property.
      fortinet.fmgdevice.fmgd_system_vdomproperty:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        system_vdomproperty:
          name: "your value" # Required variable, string
          # custom_service: <list or integer>
          # description: <string>
          # dialup_tunnel: <list or integer>
          # firewall_address: <list or integer>
          # firewall_addrgrp: <list or integer>
          # firewall_policy: <list or integer>
          # ipsec_phase1: <list or integer>
          # ipsec_phase1_interface: <list or integer>
          # ipsec_phase2: <list or integer>
          # ipsec_phase2_interface: <list or integer>
          # log_disk_quota: <list or integer>
          # onetime_schedule: <list or integer>
          # proxy: <list or integer>
          # recurring_schedule: <list or integer>
          # service_group: <list or integer>
          # session: <list or integer>
          # snmp_index: <integer>
          # sslvpn: <list or integer>
          # user: <list or integer>
          # user_group: <list or integer>
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
        '/pm/config/device/{device}/global/system/vdom-property'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_vdomproperty': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'custom-service': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'dialup-tunnel': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'firewall-address': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'firewall-addrgrp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'firewall-policy': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'ipsec-phase1': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'ipsec-phase1-interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'ipsec-phase2': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'ipsec-phase2-interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'log-disk-quota': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'onetime-schedule': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'proxy': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'recurring-schedule': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'service-group': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'session': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'snmp-index': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'sslvpn': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'user': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'user-group': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_vdomproperty'),
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
