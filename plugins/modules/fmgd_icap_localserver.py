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
module: fmgd_icap_localserver
short_description: Device vdom icap local server
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
  icap_localserver:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      icap_incoming_port:
        aliases: ['icap-incoming-port']
        type: int
        description: Accept incoming ICAP requests on one or more ports
      icap_incoming_ssl_port:
        aliases: ['icap-incoming-ssl-port']
        type: int
        description: Accept incoming secured ICAP requests on one or more ports
      icap_server_id:
        aliases: ['icap-server-id']
        type: int
        description: ICAP local server id.
      icap_service:
        aliases: ['icap-service']
        type: list
        elements: dict
        description: Icap service.
        suboptions:
          av_profile:
            aliases: ['av-profile']
            type: list
            elements: str
            description: Name of an existing Antivirus profile.
          dlp_profile:
            aliases: ['dlp-profile']
            type: list
            elements: str
            description: Dlp profile.
          dlp_sensor:
            aliases: ['dlp-sensor']
            type: list
            elements: str
            description: Name of an existing DLP sensor.
          extension_headers:
            aliases: ['extension-headers']
            type: list
            elements: str
            description: Extension headers.
            choices: ['X-Virus-id', 'X-Infection-Found', 'X-Violation-Found']
          image_analyzer_profile:
            aliases: ['image-analyzer-profile']
            type: list
            elements: str
            description: Image analyzer profile.
          name:
            type: str
            description: Name of ICAP service profile.
          profile_protocol_options:
            aliases: ['profile-protocol-options']
            type: list
            elements: str
            description: Profile protocol options.
          service_id:
            aliases: ['service-id']
            type: int
            description: ID of the ICAP server service.
          webfilter_profile:
            aliases: ['webfilter-profile']
            type: list
            elements: str
            description: Name of an existing Web filter profile.
      incoming_ip:
        aliases: ['incoming-ip']
        type: str
        description: Restrict the ICAP server to only accept sessions from this IP address.
      incoming_ipv6:
        aliases: ['incoming-ipv6']
        type: str
        description: Restrict the ICAP server to only accept sessions from this IPv6 address.
      interface:
        type: list
        elements: str
        description: Interface name
      message_preview:
        aliases: ['message-preview']
        type: str
        description: Message preview.
        choices: ['disable', 'enable']
      secure_connection:
        aliases: ['secure-connection']
        type: str
        description: Enable/disable status for secured icap server network profile.
        choices: ['disable', 'enable']
      srcaddr:
        type: list
        elements: str
        description: Source address name.
      ssl_cert:
        aliases: ['ssl-cert']
        type: list
        elements: str
        description: SSL certificate for SSL interception.
      status:
        type: str
        description: Enable/disable status for icap server network profile.
        choices: ['disable', 'enable']
      status_ipv6:
        aliases: ['status-ipv6']
        type: str
        description: Enable/disable status for icap server service ipv6.
        choices: ['disable', 'enable']
      strict_scheme_check:
        aliases: ['strict-scheme-check']
        type: str
        description: Enable/disable strict check of scheme.
        choices: ['disable', 'enable']
      timeout:
        type: int
        description: Timeout.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Device vdom icap local server
      fortinet.fmgdevice.fmgd_icap_localserver:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        icap_localserver:
          # icap_incoming_port: <integer>
          # icap_incoming_ssl_port: <integer>
          # icap_server_id: <integer>
          # icap_service:
          #   - av_profile: <list or string>
          #     dlp_profile: <list or string>
          #     dlp_sensor: <list or string>
          #     extension_headers: ["X-Virus-id", "X-Infection-Found", "X-Violation-Found"]
          #     image_analyzer_profile: <list or string>
          #     name: <string>
          #     profile_protocol_options: <list or string>
          #     service_id: <integer>
          #     webfilter_profile: <list or string>
          # incoming_ip: <string>
          # incoming_ipv6: <string>
          # interface: <list or string>
          # message_preview: <value in [disable, enable]>
          # secure_connection: <value in [disable, enable]>
          # srcaddr: <list or string>
          # ssl_cert: <list or string>
          # status: <value in [disable, enable]>
          # status_ipv6: <value in [disable, enable]>
          # strict_scheme_check: <value in [disable, enable]>
          # timeout: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/icap/local-server'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'icap_localserver': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'icap-incoming-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'icap-incoming-ssl-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'icap-server-id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'icap-service': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'av-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'dlp-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'dlp-sensor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'extension-headers': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': ['X-Virus-id', 'X-Infection-Found', 'X-Violation-Found'],
                            'elements': 'str'
                        },
                        'image-analyzer-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'profile-protocol-options': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'service-id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'webfilter-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'incoming-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'incoming-ipv6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'interface': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'message-preview': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'secure-connection': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcaddr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ssl-cert': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status-ipv6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'strict-scheme-check': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'timeout': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'icap_localserver'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
