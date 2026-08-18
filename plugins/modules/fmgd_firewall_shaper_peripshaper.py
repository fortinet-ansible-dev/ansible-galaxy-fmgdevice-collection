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
module: fmgd_firewall_shaper_peripshaper
short_description: Configure per-IP traffic shaper.
version_added: "1.1.0"
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
  firewall_shaper_peripshaper:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      bandwidth_unit:
        aliases: ['bandwidth-unit']
        type: str
        description: Unit of measurement for maximum bandwidth for this shaper
        choices: ['kbps', 'mbps', 'gbps']
      diffserv_forward:
        aliases: ['diffserv-forward']
        type: str
        description: Enable/disable changing the Forward
        choices: ['disable', 'enable']
      diffserv_reverse:
        aliases: ['diffserv-reverse']
        type: str
        description: Enable/disable changing the Reverse
        choices: ['disable', 'enable']
      diffservcode_forward:
        aliases: ['diffservcode-forward']
        type: str
        description: Forward
      diffservcode_rev:
        aliases: ['diffservcode-rev']
        type: str
        description: Reverse
      max_bandwidth:
        aliases: ['max-bandwidth']
        type: int
        description: Upper bandwidth limit enforced by this shaper
      max_concurrent_session:
        aliases: ['max-concurrent-session']
        type: int
        description: Maximum number of concurrent sessions allowed by this shaper
      max_concurrent_tcp_session:
        aliases: ['max-concurrent-tcp-session']
        type: int
        description: Maximum number of concurrent TCP sessions allowed by this shaper
      max_concurrent_udp_session:
        aliases: ['max-concurrent-udp-session']
        type: int
        description: Maximum number of concurrent UDP sessions allowed by this shaper
      name:
        type: str
        description: Traffic shaper name.
        required: true
      fabric_force_sync:
        aliases: ['fabric-force-sync']
        type: str
        description: Enable/disable forced synchronization of configuration objects from the root FortiGate unit to the downstream devices.
        choices: ['disable', 'enable']
      fabric_object:
        aliases: ['fabric-object']
        type: str
        description: Security Fabric global object setting.
        choices: ['disable', 'enable']
      fabric_object_source:
        aliases: ['fabric-object-source']
        type: str
        description: Source of truth for fabric object.
        choices: ['member', 'local', 'root']
      uuid:
        type: str
        description: Universally Unique Identifier
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure per-IP traffic shaper.
      fortinet.fmgdevice.fmgd_firewall_shaper_peripshaper:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_shaper_peripshaper:
          name: "your value" # Required variable, string
          # bandwidth_unit: <value in [kbps, mbps, gbps]>
          # diffserv_forward: <value in [disable, enable]>
          # diffserv_reverse: <value in [disable, enable]>
          # diffservcode_forward: <string>
          # diffservcode_rev: <string>
          # max_bandwidth: <integer>
          # max_concurrent_session: <integer>
          # max_concurrent_tcp_session: <integer>
          # max_concurrent_udp_session: <integer>
          # fabric_force_sync: <value in [disable, enable]>
          # fabric_object: <value in [disable, enable]>
          # fabric_object_source: <value in [member, local, root]>
          # uuid: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/shaper/per-ip-shaper'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_shaper_peripshaper': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'bandwidth-unit': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['kbps', 'mbps', 'gbps'], 'type': 'str'},
                'diffserv-forward': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diffserv-reverse': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diffservcode-forward': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'diffservcode-rev': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'max-bandwidth': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'max-concurrent-session': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'max-concurrent-tcp-session': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'max-concurrent-udp-session': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'fabric-force-sync': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object-source': {'v_range': [['8.0.0', '']], 'choices': ['member', 'local', 'root'], 'type': 'str'},
                'uuid': {'v_range': [['8.0.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_shaper_peripshaper'),
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
