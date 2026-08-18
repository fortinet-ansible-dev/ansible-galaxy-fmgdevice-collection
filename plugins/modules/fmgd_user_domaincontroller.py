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
module: fmgd_user_domaincontroller
short_description: Configure domain controller entries.
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
  user_domaincontroller:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      ad_mode:
        aliases: ['ad-mode']
        type: str
        description: Set Active Directory mode.
        choices: ['none', 'ds', 'lds']
      adlds_dn:
        aliases: ['adlds-dn']
        type: str
        description: AD LDS distinguished name.
      adlds_ip_address:
        aliases: ['adlds-ip-address']
        type: str
        description: AD LDS IPv4 address.
      adlds_ip6:
        aliases: ['adlds-ip6']
        type: str
        description: AD LDS IPv6 address.
      adlds_port:
        aliases: ['adlds-port']
        type: int
        description: Port number of AD LDS service
      change_detection:
        aliases: ['change-detection']
        type: str
        description: Enable/disable detection of a configuration change in the Active Directory server.
        choices: ['disable', 'enable']
      change_detection_period:
        aliases: ['change-detection-period']
        type: int
        description: Minutes to detect a configuration change in the Active Directory server
      dns_srv_lookup:
        aliases: ['dns-srv-lookup']
        type: str
        description: Enable/disable DNS service lookup.
        choices: ['disable', 'enable']
      domain_name:
        aliases: ['domain-name']
        type: str
        description: Domain DNS name.
      domain_name_src:
        aliases: ['domain-name-src']
        type: str
        description: Domain name src.
        choices: ['server', 'client']
      extra_server:
        aliases: ['extra-server']
        type: list
        elements: dict
        description: Extra server.
        suboptions:
          id:
            type: int
            description: Server ID.
          ip_address:
            aliases: ['ip-address']
            type: str
            description: Domain controller IP address.
          port:
            type: int
            description: Port to be used for communication with the domain controller
          source_ip_address:
            aliases: ['source-ip-address']
            type: str
            description: FortiGate IPv4 address to be used for communication with the domain controller.
          source_port:
            aliases: ['source-port']
            type: int
            description: Source port to be used for communication with the domain controller.
      hostname:
        type: str
        description: Hostname of the server to connect to.
      interface:
        type: list
        elements: str
        description: Specify outgoing interface to reach server.
      interface_select_method:
        aliases: ['interface-select-method']
        type: str
        description: Specify how to select outgoing interface to reach server.
        choices: ['auto', 'sdwan', 'specify']
      ip_address:
        aliases: ['ip-address']
        type: str
        description: Domain controller IPv4 address.
      ip6:
        type: str
        description: Domain controller IPv6 address.
      ldap_server:
        aliases: ['ldap-server']
        type: list
        elements: str
        description: LDAP server name
      name:
        type: str
        description: Domain controller entry name.
        required: true
      password:
        type: list
        elements: str
        description: Password for specified username.
      port:
        type: int
        description: Port to be used for communication with the domain controller
      replication_port:
        aliases: ['replication-port']
        type: int
        description: Port to be used for communication with the domain controller for replication service.
      source_ip_address:
        aliases: ['source-ip-address']
        type: str
        description: FortiGate IPv4 address to be used for communication with the domain controller.
      source_ip6:
        aliases: ['source-ip6']
        type: str
        description: FortiGate IPv6 address to be used for communication with the domain controller.
      source_port:
        aliases: ['source-port']
        type: int
        description: Source port to be used for communication with the domain controller.
      username:
        type: str
        description: User name to sign in with.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure domain controller entries.
      fortinet.fmgdevice.fmgd_user_domaincontroller:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        user_domaincontroller:
          name: "your value" # Required variable, string
          # ad_mode: <value in [none, ds, lds]>
          # adlds_dn: <string>
          # adlds_ip_address: <string>
          # adlds_ip6: <string>
          # adlds_port: <integer>
          # change_detection: <value in [disable, enable]>
          # change_detection_period: <integer>
          # dns_srv_lookup: <value in [disable, enable]>
          # domain_name: <string>
          # domain_name_src: <value in [server, client]>
          # extra_server:
          #   - id: <integer>
          #     ip_address: <string>
          #     port: <integer>
          #     source_ip_address: <string>
          #     source_port: <integer>
          # hostname: <string>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # ip_address: <string>
          # ip6: <string>
          # ldap_server: <list or string>
          # password: <list or string>
          # port: <integer>
          # replication_port: <integer>
          # source_ip_address: <string>
          # source_ip6: <string>
          # source_port: <integer>
          # username: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/user/domain-controller'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'user_domaincontroller': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'ad-mode': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'ds', 'lds'], 'type': 'str'},
                'adlds-dn': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'adlds-ip-address': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'adlds-ip6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'adlds-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'change-detection': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'change-detection-period': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'dns-srv-lookup': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'domain-name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'domain-name-src': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['server', 'client'], 'type': 'str'},
                'extra-server': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'ip-address': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'source-ip-address': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'source-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'hostname': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'interface': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'ip-address': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'ip6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'ldap-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'password': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'replication-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'source-ip-address': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'source-ip6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'source-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'username': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_domaincontroller'),
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
