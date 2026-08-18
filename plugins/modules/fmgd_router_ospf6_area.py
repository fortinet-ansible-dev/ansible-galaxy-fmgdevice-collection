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
module: fmgd_router_ospf6_area
short_description: OSPF6 area configuration.
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
  router_ospf6_area:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      authentication:
        type: str
        description: Authentication mode.
        choices: ['none', 'ah', 'esp']
      default_cost:
        aliases: ['default-cost']
        type: int
        description: Summary default cost of stub or NSSA area.
      id:
        type: str
        description: Area entry IP address.
        required: true
      ipsec_auth_alg:
        aliases: ['ipsec-auth-alg']
        type: str
        description: Authentication algorithm.
        choices: ['md5', 'sha1', 'sha256', 'sha384', 'sha512']
      ipsec_enc_alg:
        aliases: ['ipsec-enc-alg']
        type: str
        description: Encryption algorithm.
        choices: ['null', 'des', '3des', 'aes128', 'aes192', 'aes256']
      ipsec_keys:
        aliases: ['ipsec-keys']
        type: list
        elements: dict
        description: Ipsec keys.
        suboptions:
          auth_key:
            aliases: ['auth-key']
            type: list
            elements: str
            description: Authentication key.
          enc_key:
            aliases: ['enc-key']
            type: list
            elements: str
            description: Encryption key.
          spi:
            type: int
            description: Security Parameters Index.
      key_rollover_interval:
        aliases: ['key-rollover-interval']
        type: int
        description: Key roll-over interval.
      nssa_default_information_originate:
        aliases: ['nssa-default-information-originate']
        type: str
        description: Enable/disable originate type 7 default into NSSA area.
        choices: ['disable', 'enable']
      nssa_default_information_originate_metric:
        aliases: ['nssa-default-information-originate-metric']
        type: int
        description: OSPFv3 default metric.
      nssa_default_information_originate_metric_type:
        aliases: ['nssa-default-information-originate-metric-type']
        type: str
        description: OSPFv3 metric type for default routes.
        choices: ['1', '2']
      nssa_redistribution:
        aliases: ['nssa-redistribution']
        type: str
        description: Enable/disable redistribute into NSSA area.
        choices: ['disable', 'enable']
      nssa_translator_role:
        aliases: ['nssa-translator-role']
        type: str
        description: NSSA translator role type.
        choices: ['candidate', 'never', 'always']
      range:
        type: list
        elements: dict
        description: Range.
        suboptions:
          advertise:
            type: str
            description: Enable/disable advertise status.
            choices: ['disable', 'enable']
          id:
            type: int
            description: Range entry ID.
          prefix6:
            type: str
            description: IPv6 prefix.
      stub_type:
        aliases: ['stub-type']
        type: str
        description: Stub summary setting.
        choices: ['summary', 'no-summary']
      type:
        type: str
        description: Area type setting.
        choices: ['regular', 'nssa', 'stub']
      virtual_link:
        aliases: ['virtual-link']
        type: list
        elements: dict
        description: Virtual link.
        suboptions:
          authentication:
            type: str
            description: Authentication mode.
            choices: ['none', 'ah', 'esp', 'area']
          dead_interval:
            aliases: ['dead-interval']
            type: int
            description: Dead interval.
          hello_interval:
            aliases: ['hello-interval']
            type: int
            description: Hello interval.
          ipsec_auth_alg:
            aliases: ['ipsec-auth-alg']
            type: str
            description: Authentication algorithm.
            choices: ['md5', 'sha1', 'sha256', 'sha384', 'sha512']
          ipsec_enc_alg:
            aliases: ['ipsec-enc-alg']
            type: str
            description: Encryption algorithm.
            choices: ['null', 'des', '3des', 'aes128', 'aes192', 'aes256']
          ipsec_keys:
            aliases: ['ipsec-keys']
            type: list
            elements: dict
            description: Ipsec keys.
            suboptions:
              auth_key:
                aliases: ['auth-key']
                type: list
                elements: str
                description: Authentication key.
              enc_key:
                aliases: ['enc-key']
                type: list
                elements: str
                description: Encryption key.
              spi:
                type: int
                description: Security Parameters Index.
          key_rollover_interval:
            aliases: ['key-rollover-interval']
            type: int
            description: Key roll-over interval.
          name:
            type: str
            description: Virtual link entry name.
          peer:
            type: str
            description: A.
          retransmit_interval:
            aliases: ['retransmit-interval']
            type: int
            description: Retransmit interval.
          transmit_delay:
            aliases: ['transmit-delay']
            type: int
            description: Transmit delay.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: OSPF6 area configuration.
      fortinet.fmgdevice.fmgd_router_ospf6_area:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        router_ospf6_area:
          id: "your value" # Required variable, string
          # authentication: <value in [none, ah, esp]>
          # default_cost: <integer>
          # ipsec_auth_alg: <value in [md5, sha1, sha256, ...]>
          # ipsec_enc_alg: <value in [null, des, 3des, ...]>
          # ipsec_keys:
          #   - auth_key: <list or string>
          #     enc_key: <list or string>
          #     spi: <integer>
          # key_rollover_interval: <integer>
          # nssa_default_information_originate: <value in [disable, enable]>
          # nssa_default_information_originate_metric: <integer>
          # nssa_default_information_originate_metric_type: <value in [1, 2]>
          # nssa_redistribution: <value in [disable, enable]>
          # nssa_translator_role: <value in [candidate, never, always]>
          # range:
          #   - advertise: <value in [disable, enable]>
          #     id: <integer>
          #     prefix6: <string>
          # stub_type: <value in [summary, no-summary]>
          # type: <value in [regular, nssa, stub]>
          # virtual_link:
          #   - authentication: <value in [none, ah, esp, ...]>
          #     dead_interval: <integer>
          #     hello_interval: <integer>
          #     ipsec_auth_alg: <value in [md5, sha1, sha256, ...]>
          #     ipsec_enc_alg: <value in [null, des, 3des, ...]>
          #     ipsec_keys:
          #       - auth_key: <list or string>
          #         enc_key: <list or string>
          #         spi: <integer>
          #     key_rollover_interval: <integer>
          #     name: <string>
          #     peer: <string>
          #     retransmit_interval: <integer>
          #     transmit_delay: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'router_ospf6_area': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'authentication': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'ah', 'esp'], 'type': 'str'},
                'default-cost': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'ipsec-auth-alg': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['md5', 'sha1', 'sha256', 'sha384', 'sha512'],
                    'type': 'str'
                },
                'ipsec-enc-alg': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['null', 'des', '3des', 'aes128', 'aes192', 'aes256'],
                    'type': 'str'
                },
                'ipsec-keys': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'no_log': True,
                    'type': 'list',
                    'options': {
                        'auth-key': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'enc-key': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'spi': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'key-rollover-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                'nssa-default-information-originate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nssa-default-information-originate-metric': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'nssa-default-information-originate-metric-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['1', '2'], 'type': 'str'},
                'nssa-redistribution': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nssa-translator-role': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['candidate', 'never', 'always'], 'type': 'str'},
                'range': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'advertise': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'prefix6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'stub-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['summary', 'no-summary'], 'type': 'str'},
                'type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['regular', 'nssa', 'stub'], 'type': 'str'},
                'virtual-link': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'authentication': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'ah', 'esp', 'area'], 'type': 'str'},
                        'dead-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'hello-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'ipsec-auth-alg': {
                            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                            'choices': ['md5', 'sha1', 'sha256', 'sha384', 'sha512'],
                            'type': 'str'
                        },
                        'ipsec-enc-alg': {
                            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                            'choices': ['null', 'des', '3des', 'aes128', 'aes192', 'aes256'],
                            'type': 'str'
                        },
                        'ipsec-keys': {
                            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                            'no_log': True,
                            'type': 'list',
                            'options': {
                                'auth-key': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                                'enc-key': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                                'spi': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'key-rollover-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'peer': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'retransmit-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'transmit-delay': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_ospf6_area'),
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
