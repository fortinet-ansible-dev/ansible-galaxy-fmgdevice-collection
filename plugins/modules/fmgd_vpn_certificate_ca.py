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
module: fmgd_vpn_certificate_ca
short_description: CA certificate.
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
  vpn_certificate_ca:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      _private_key:
        type: str
        description: Private key.
      auto_update_days:
        aliases: ['auto-update-days']
        type: int
        description: Number of days to wait before requesting an updated CA certificate
      auto_update_days_warning:
        aliases: ['auto-update-days-warning']
        type: int
        description: Number of days before an expiry-warning message is generated
      ca:
        type: str
        description: CA certificate as a PEM file.
      ca_identifier:
        aliases: ['ca-identifier']
        type: str
        description: CA identifier of the SCEP server.
      last_updated:
        aliases: ['last-updated']
        type: int
        description: Time at which CA was last updated.
      name:
        type: str
        description: Name.
        required: true
      obsolete:
        type: str
        description: Enable/disable this CA as obsoleted.
        choices: ['disable', 'enable']
      range:
        type: str
        description: Either global or VDOM IP address range for the CA certificate.
        choices: ['global', 'vdom']
      scep_url:
        aliases: ['scep-url']
        type: str
        description: URL of the SCEP server.
      source:
        type: str
        description: CA certificate source type.
        choices: ['factory', 'user', 'bundle']
      source_ip:
        aliases: ['source-ip']
        type: str
        description: Source IP address for communications to the SCEP server.
      ssl_inspection_trusted:
        aliases: ['ssl-inspection-trusted']
        type: str
        description: Enable/disable this CA as a trusted CA for SSL inspection.
        choices: ['disable', 'enable']
      fabric_ca:
        aliases: ['fabric-ca']
        type: str
        description: Enable/disable synchronization of CA across Security Fabric.
        choices: ['disable', 'enable']
      non_fabric_name:
        aliases: ['non-fabric-name']
        type: str
        description: Name used prior to becoming a Security Fabric synchronized CA.
      est_url:
        aliases: ['est-url']
        type: str
        description: URL of the EST server.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: CA certificate.
      fortinet.fmgdevice.fmgd_vpn_certificate_ca:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        vpn_certificate_ca:
          name: "your value" # Required variable, string
          # _private_key: <string>
          # auto_update_days: <integer>
          # auto_update_days_warning: <integer>
          # ca: <string>
          # ca_identifier: <string>
          # last_updated: <integer>
          # obsolete: <value in [disable, enable]>
          # range: <value in [global, vdom]>
          # scep_url: <string>
          # source: <value in [factory, user, bundle]>
          # source_ip: <string>
          # ssl_inspection_trusted: <value in [disable, enable]>
          # fabric_ca: <value in [disable, enable]>
          # non_fabric_name: <string>
          # est_url: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/vpn/certificate/ca'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'vpn_certificate_ca': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                '_private_key': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'str'},
                'auto-update-days': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'auto-update-days-warning': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'ca': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'ca-identifier': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'last-updated': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'obsolete': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'range': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['global', 'vdom'], 'type': 'str'},
                'scep-url': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'source': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['factory', 'user', 'bundle'], 'type': 'str'},
                'source-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'ssl-inspection-trusted': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-ca': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'non-fabric-name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'est-url': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpn_certificate_ca'),
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
