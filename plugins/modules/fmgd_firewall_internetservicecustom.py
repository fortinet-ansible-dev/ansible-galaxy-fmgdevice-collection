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
module: fmgd_firewall_internetservicecustom
short_description: Configure custom Internet Services.
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
  firewall_internetservicecustom:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      comment:
        type: str
        description: Comment.
      entry:
        type: list
        elements: dict
        description: Entry.
        suboptions:
          addr_mode:
            aliases: ['addr-mode']
            type: str
            description: Address mode
            choices: ['ipv4', 'ipv6']
          dst:
            type: list
            elements: str
            description: Destination address or address group name.
          dst6:
            type: list
            elements: str
            description: Destination address6 or address6 group name.
          id:
            type: int
            description: Entry ID
          port_range:
            aliases: ['port-range']
            type: list
            elements: dict
            description: Port range.
            suboptions:
              end_port:
                aliases: ['end-port']
                type: int
                description: Integer value for ending TCP/UDP/SCTP destination port in range
              id:
                type: int
                description: Custom entry port range ID.
              start_port:
                aliases: ['start-port']
                type: int
                description: Integer value for starting TCP/UDP/SCTP destination port in range
          protocol:
            type: int
            description: Integer value for the protocol type as defined by IANA
      id:
        type: int
        description: Internet Service ID.
        required: true
      name:
        type: str
        description: Internet Service name.
      reputation:
        type: int
        description: Reputation level of the custom Internet Service.
      disable_entry:
        aliases: ['disable-entry']
        type: list
        elements: dict
        description: Disable entry.
        suboptions:
          id:
            type: int
            description: Disable entry ID.
          ip_range:
            aliases: ['ip-range']
            type: list
            elements: dict
            description: Ip range.
            suboptions:
              end_ip:
                aliases: ['end-ip']
                type: str
                description: End IP address.
              id:
                type: int
                description: Disable entry range ID.
              start_ip:
                aliases: ['start-ip']
                type: str
                description: Start IP address.
          port:
            type: list
            elements: int
            description: Integer value for the TCP/IP port
          protocol:
            type: int
            description: Integer value for the protocol type as defined by IANA
      master_service_id:
        aliases: ['master-service-id']
        type: list
        elements: str
        description: Internet Service ID in the Internet Service database.
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
    - name: Configure custom Internet Services.
      fortinet.fmgdevice.fmgd_firewall_internetservicecustom:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_internetservicecustom:
          id: 0 # Required variable, integer
          # comment: <string>
          # entry:
          #   - addr_mode: <value in [ipv4, ipv6]>
          #     dst: <list or string>
          #     dst6: <list or string>
          #     id: <integer>
          #     port_range:
          #       - end_port: <integer>
          #         id: <integer>
          #         start_port: <integer>
          #     protocol: <integer>
          # name: <string>
          # reputation: <integer>
          # disable_entry:
          #   - id: <integer>
          #     ip_range:
          #       - end_ip: <string>
          #         id: <integer>
          #         start_ip: <string>
          #     port: <list or integer>
          #     protocol: <integer>
          # master_service_id: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-custom'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_internetservicecustom': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'comment': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'entry': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'addr-mode': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                        'dst': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'dst6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'port-range': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'end-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                                'start-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'protocol': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'reputation': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'disable-entry': {
                    'v_range': [['7.4.8', '7.4.11']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.4.8', '7.4.11']], 'type': 'int'},
                        'ip-range': {
                            'v_range': [['7.4.8', '7.4.11']],
                            'type': 'list',
                            'options': {
                                'end-ip': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'},
                                'id': {'v_range': [['7.4.8', '7.4.11']], 'type': 'int'},
                                'start-ip': {'v_range': [['7.4.8', '7.4.11']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'port': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'int'},
                        'protocol': {'v_range': [['7.4.8', '7.4.11']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'master-service-id': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'str'},
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_internetservicecustom'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
