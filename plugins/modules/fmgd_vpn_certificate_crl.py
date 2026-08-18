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
module: fmgd_vpn_certificate_crl
short_description: Certificate Revocation List as a PEM file.
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
  vpn_certificate_crl:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      crl:
        type: str
        description: Certificate Revocation List as a PEM file.
      http_url:
        aliases: ['http-url']
        type: str
        description: HTTP server URL for CRL auto-update.
      last_updated:
        aliases: ['last-updated']
        type: int
        description: Time at which CRL was last updated.
      ldap_password:
        aliases: ['ldap-password']
        type: list
        elements: str
        description: LDAP server user password.
      ldap_server:
        aliases: ['ldap-server']
        type: list
        elements: str
        description: LDAP server name for CRL auto-update.
      ldap_username:
        aliases: ['ldap-username']
        type: str
        description: LDAP server user name.
      name:
        type: str
        description: Name.
        required: true
      range:
        type: str
        description: Either global or VDOM IP address range for the certificate.
        choices: ['global', 'vdom']
      scep_cert:
        aliases: ['scep-cert']
        type: list
        elements: str
        description: Local certificate for SCEP communication for CRL auto-update.
      scep_url:
        aliases: ['scep-url']
        type: str
        description: SCEP server URL for CRL auto-update.
      source:
        type: str
        description: Certificate source type.
        choices: ['factory', 'user', 'bundle', 'fortiguard']
      source_ip:
        aliases: ['source-ip']
        type: str
        description: Source IP address for communications to a HTTP or SCEP CA server.
      update_interval:
        aliases: ['update-interval']
        type: int
        description: Time in seconds before the FortiGate checks for an updated CRL.
      update_vdom:
        aliases: ['update-vdom']
        type: list
        elements: str
        description: VDOM for CRL update.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Certificate Revocation List as a PEM file.
      fortinet.fmgdevice.fmgd_vpn_certificate_crl:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        vpn_certificate_crl:
          name: "your value" # Required variable, string
          # crl: <string>
          # http_url: <string>
          # last_updated: <integer>
          # ldap_password: <list or string>
          # ldap_server: <list or string>
          # ldap_username: <string>
          # range: <value in [global, vdom]>
          # scep_cert: <list or string>
          # scep_url: <string>
          # source: <value in [factory, user, bundle, ...]>
          # source_ip: <string>
          # update_interval: <integer>
          # update_vdom: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/vpn/certificate/crl'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'vpn_certificate_crl': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'crl': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'http-url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'last-updated': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'ldap-password': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'ldap-server': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ldap-username': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'range': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['global', 'vdom'], 'type': 'str'},
                'scep-cert': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'scep-url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'source': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['factory', 'user', 'bundle', 'fortiguard'], 'type': 'str'},
                'source-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'update-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'update-vdom': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpn_certificate_crl'),
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
