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
module: fmgd_firewall_ssl_setting
short_description: SSL proxy settings.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  firewall_ssl_setting:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      abbreviate_handshake:
        aliases: ['abbreviate-handshake']
        type: str
        description: Enable/disable use of SSL abbreviated handshake.
        choices: ['disable', 'enable']
      cert_cache_capacity:
        aliases: ['cert-cache-capacity']
        type: int
        description: Maximum capacity of the host certificate cache
      cert_cache_timeout:
        aliases: ['cert-cache-timeout']
        type: int
        description: Time limit to keep certificate cache
      kxp_queue_threshold:
        aliases: ['kxp-queue-threshold']
        type: int
        description: Maximum length of the CP KXP queue.
      no_matching_cipher_action:
        aliases: ['no-matching-cipher-action']
        type: str
        description: Bypass or drop the connection when no matching cipher is found.
        choices: ['drop', 'bypass']
      proxy_connect_timeout:
        aliases: ['proxy-connect-timeout']
        type: int
        description: Time limit to make an internal connection to the appropriate proxy process
      session_cache_capacity:
        aliases: ['session-cache-capacity']
        type: int
        description: Capacity of the SSL session cache
      session_cache_timeout:
        aliases: ['session-cache-timeout']
        type: int
        description: Time limit to keep SSL session state
      ssl_dh_bits:
        aliases: ['ssl-dh-bits']
        type: str
        description: Bit-size of Diffie-Hellman
        choices: ['768', '1024', '1536', '2048']
      ssl_queue_threshold:
        aliases: ['ssl-queue-threshold']
        type: int
        description: Maximum length of the CP SSL queue.
      ssl_send_empty_frags:
        aliases: ['ssl-send-empty-frags']
        type: str
        description: Enable/disable sending empty fragments to avoid attack on CBC IV
        choices: ['disable', 'enable']
      cert_manager_cache_timeout:
        aliases: ['cert-manager-cache-timeout']
        type: int
        description: Time limit for certificate manager to keep FortiGate re-signed server certificate
      resigned_short_lived_certificate:
        aliases: ['resigned-short-lived-certificate']
        type: str
        description: Enable/disable short-lived certificate.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: SSL proxy settings.
      fortinet.fmgdevice.fmgd_firewall_ssl_setting:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        firewall_ssl_setting:
          # abbreviate_handshake: <value in [disable, enable]>
          # cert_cache_capacity: <integer>
          # cert_cache_timeout: <integer>
          # kxp_queue_threshold: <integer>
          # no_matching_cipher_action: <value in [drop, bypass]>
          # proxy_connect_timeout: <integer>
          # session_cache_capacity: <integer>
          # session_cache_timeout: <integer>
          # ssl_dh_bits: <value in [768, 1024, 1536, ...]>
          # ssl_queue_threshold: <integer>
          # ssl_send_empty_frags: <value in [disable, enable]>
          # cert_manager_cache_timeout: <integer>
          # resigned_short_lived_certificate: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/firewall/ssl/setting'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'firewall_ssl_setting': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'abbreviate-handshake': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cert-cache-capacity': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'cert-cache-timeout': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'kxp-queue-threshold': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'no-matching-cipher-action': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['drop', 'bypass'], 'type': 'str'},
                'proxy-connect-timeout': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'session-cache-capacity': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'session-cache-timeout': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'ssl-dh-bits': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['768', '1024', '1536', '2048'], 'type': 'str'},
                'ssl-queue-threshold': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'ssl-send-empty-frags': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cert-manager-cache-timeout': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'resigned-short-lived-certificate': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_ssl_setting'),
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
