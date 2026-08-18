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
module: fmgd_firewall_accessproxyvirtualhost
short_description: Configure Access Proxy virtual hosts.
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
  firewall_accessproxyvirtualhost:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      host:
        type: str
        description: The host name.
      host_type:
        aliases: ['host-type']
        type: str
        description: Type of host pattern.
        choices: ['sub-string', 'wildcard', 'fqdn']
      name:
        type: str
        description: Virtual host name.
        required: true
      replacemsg_group:
        aliases: ['replacemsg-group']
        type: list
        elements: str
        description: Access-proxy-virtual-host replacement message override group.
      ssl_certificate:
        aliases: ['ssl-certificate']
        type: list
        elements: str
        description: SSL certificates for this host.
      client_cert:
        aliases: ['client-cert']
        type: str
        description: Enable/disable requesting client certificate.
        choices: ['disable', 'enable']
      empty_cert_action:
        aliases: ['empty-cert-action']
        type: str
        description: Action for an empty client certificate.
        choices: ['block', 'accept', 'accept-unmanageable']
      user_agent_detect:
        aliases: ['user-agent-detect']
        type: str
        description: Enable/disable detecting device type by HTTP user-agent if no client certificate is provided.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure Access Proxy virtual hosts.
      fortinet.fmgdevice.fmgd_firewall_accessproxyvirtualhost:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_accessproxyvirtualhost:
          name: "your value" # Required variable, string
          # host: <string>
          # host_type: <value in [sub-string, wildcard, fqdn]>
          # replacemsg_group: <list or string>
          # ssl_certificate: <list or string>
          # client_cert: <value in [disable, enable]>
          # empty_cert_action: <value in [block, accept, accept-unmanageable]>
          # user_agent_detect: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy-virtual-host'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_accessproxyvirtualhost': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'host': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'host-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['sub-string', 'wildcard', 'fqdn'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'replacemsg-group': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ssl-certificate': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'client-cert': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'empty-cert-action': {'v_range': [['7.6.4', '']], 'choices': ['block', 'accept', 'accept-unmanageable'], 'type': 'str'},
                'user-agent-detect': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_accessproxyvirtualhost'),
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
