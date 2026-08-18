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
module: fmgd_wireless_snmp
short_description: Configure SNMP.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  vdom:
    description: The parameter (vdom) in requested url.
    type: str
    required: true
  wireless_snmp:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      community:
        type: list
        elements: dict
        description: Community.
        suboptions:
          hosts:
            type: list
            elements: dict
            description: Hosts.
            suboptions:
              id:
                type: int
                description: Host entry ID.
              ip:
                type: str
                description: IPv4 address of the SNMP manager
          id:
            type: int
            description: Community ID.
          name:
            type: str
            description: Community name.
          query_v1_status:
            aliases: ['query-v1-status']
            type: str
            description: Enable/disable SNMP v1 queries.
            choices: ['disable', 'enable']
          query_v2c_status:
            aliases: ['query-v2c-status']
            type: str
            description: Enable/disable SNMP v2c queries.
            choices: ['disable', 'enable']
          status:
            type: str
            description: Enable/disable this SNMP community.
            choices: ['disable', 'enable']
          trap_v1_status:
            aliases: ['trap-v1-status']
            type: str
            description: Enable/disable SNMP v1 traps.
            choices: ['disable', 'enable']
          trap_v2c_status:
            aliases: ['trap-v2c-status']
            type: str
            description: Enable/disable SNMP v2c traps.
            choices: ['disable', 'enable']
          hosts6:
            type: list
            elements: dict
            description: Hosts6.
            suboptions:
              id:
                type: int
                description: Host6 entry ID.
              ipv6:
                type: str
                description: IPv6 address of the SNMP manager
      contact_info:
        aliases: ['contact-info']
        type: str
        description: Contact Information.
      engine_id:
        aliases: ['engine-id']
        type: str
        description: AC SNMP engineID string
      trap_high_cpu_threshold:
        aliases: ['trap-high-cpu-threshold']
        type: int
        description: CPU usage when trap is sent.
      trap_high_mem_threshold:
        aliases: ['trap-high-mem-threshold']
        type: int
        description: Memory usage when trap is sent.
      user:
        type: list
        elements: dict
        description: User.
        suboptions:
          auth_proto:
            aliases: ['auth-proto']
            type: str
            description: Authentication protocol.
            choices: ['md5', 'sha', 'sha224', 'sha256', 'sha384', 'sha512']
          auth_pwd:
            aliases: ['auth-pwd']
            type: list
            elements: str
            description: Password for authentication protocol.
          name:
            type: str
            description: SNMP user name.
          notify_hosts:
            aliases: ['notify-hosts']
            type: list
            elements: str
            description: Configure SNMP User Notify Hosts.
          priv_proto:
            aliases: ['priv-proto']
            type: str
            description: Privacy
            choices: ['aes', 'des', 'aes256', 'aes256cisco']
          priv_pwd:
            aliases: ['priv-pwd']
            type: list
            elements: str
            description: Password for privacy
          queries:
            type: str
            description: Enable/disable SNMP queries for this user.
            choices: ['disable', 'enable']
          security_level:
            aliases: ['security-level']
            type: str
            description: Security level for message authentication and encryption.
            choices: ['no-auth-no-priv', 'auth-no-priv', 'auth-priv']
          status:
            type: str
            description: SNMP user enable.
            choices: ['disable', 'enable']
          trap_status:
            aliases: ['trap-status']
            type: str
            description: Enable/disable traps for this SNMP user.
            choices: ['disable', 'enable']
          notify_hosts6:
            aliases: ['notify-hosts6']
            type: list
            elements: str
            description: Configure IPv6 SNMP User Notify Hosts.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure SNMP.
      fortinet.fmgdevice.fmgd_wireless_snmp:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        wireless_snmp:
          # community:
          #   - hosts:
          #       - id: <integer>
          #         ip: <string>
          #     id: <integer>
          #     name: <string>
          #     query_v1_status: <value in [disable, enable]>
          #     query_v2c_status: <value in [disable, enable]>
          #     status: <value in [disable, enable]>
          #     trap_v1_status: <value in [disable, enable]>
          #     trap_v2c_status: <value in [disable, enable]>
          #     hosts6:
          #       - id: <integer>
          #         ipv6: <string>
          # contact_info: <string>
          # engine_id: <string>
          # trap_high_cpu_threshold: <integer>
          # trap_high_mem_threshold: <integer>
          # user:
          #   - auth_proto: <value in [md5, sha, sha224, ...]>
          #     auth_pwd: <list or string>
          #     name: <string>
          #     notify_hosts: <list or string>
          #     priv_proto: <value in [aes, des, aes256, ...]>
          #     priv_pwd: <list or string>
          #     queries: <value in [disable, enable]>
          #     security_level: <value in [no-auth-no-priv, auth-no-priv, auth-priv]>
          #     status: <value in [disable, enable]>
          #     trap_status: <value in [disable, enable]>
          #     notify_hosts6: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/snmp'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wireless_snmp': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'community': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'hosts': {
                            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                                'ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'query-v1-status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'query-v2c-status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'trap-v1-status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'trap-v2c-status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'hosts6': {
                            'v_range': [['7.6.5', '']],
                            'type': 'list',
                            'options': {'id': {'v_range': [['7.6.5', '']], 'type': 'int'}, 'ipv6': {'v_range': [['7.6.5', '']], 'type': 'str'}},
                            'elements': 'dict'
                        }
                    },
                    'elements': 'dict'
                },
                'contact-info': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'engine-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'trap-high-cpu-threshold': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'trap-high-mem-threshold': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'user': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'auth-proto': {
                            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                            'choices': ['md5', 'sha', 'sha224', 'sha256', 'sha384', 'sha512'],
                            'type': 'str'
                        },
                        'auth-pwd': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'notify-hosts': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'priv-proto': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['aes', 'des', 'aes256', 'aes256cisco'], 'type': 'str'},
                        'priv-pwd': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'queries': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'security-level': {
                            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                            'choices': ['no-auth-no-priv', 'auth-no-priv', 'auth-priv'],
                            'type': 'str'
                        },
                        'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'trap-status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'notify-hosts6': {'v_range': [['7.6.5', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_snmp'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
