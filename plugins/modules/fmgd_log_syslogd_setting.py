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
module: fmgd_log_syslogd_setting
short_description: Global settings for remote syslog server.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  log_syslogd_setting:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      certificate:
        type: list
        elements: str
        description: Certificate used to communicate with Syslog server.
      custom_field_name:
        aliases: ['custom-field-name']
        type: list
        elements: dict
        description: Custom field name.
        suboptions:
          custom:
            type: str
            description: Field custom name [A-Za-z0-9_].
          id:
            type: int
            description: Entry ID.
          name:
            type: str
            description: Field name [A-Za-z0-9_].
      enc_algorithm:
        aliases: ['enc-algorithm']
        type: str
        description: Enable/disable reliable syslogging with TLS encryption.
        choices: ['high', 'low', 'disable', 'high-medium']
      facility:
        type: str
        description: Remote syslog facility.
        choices: ['kernel', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp',
                  'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert', 'clock', 'local0', 'local1',
                  'local2', 'local3', 'local4', 'local5', 'local6', 'local7']
      format:
        type: str
        description: Log format.
        choices: ['default', 'csv', 'cef', 'rfc5424', 'json', 'custom']
      interface:
        type: list
        elements: str
        description:
          - Support meta variable
          - Specify outgoing interface to reach server.
      interface_select_method:
        aliases: ['interface-select-method']
        type: str
        description: Specify how to select outgoing interface to reach server.
        choices: ['auto', 'sdwan', 'specify']
      max_log_rate:
        aliases: ['max-log-rate']
        type: int
        description: Syslog maximum log rate in MBps
      mode:
        type: str
        description: Remote syslog logging over UDP/Reliable TCP.
        choices: ['udp', 'legacy-reliable', 'reliable']
      port:
        type: int
        description: Server listen port.
      priority:
        type: str
        description: Set log transmission priority.
        choices: ['low', 'default']
      server:
        type: str
        description: Address of remote syslog server.
      ssl_min_proto_version:
        aliases: ['ssl-min-proto-version']
        type: str
        description: Minimum supported protocol version for SSL/TLS connections
        choices: ['default', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1', 'TLSv1-3']
      status:
        type: str
        description: Enable/disable remote syslog logging.
        choices: ['disable', 'enable']
      source_ip:
        aliases: ['source-ip']
        type: str
        description: Source IP address of syslog.
      source_ip_interface:
        aliases: ['source-ip-interface']
        type: list
        elements: str
        description: Source interface of syslog.
      vrf_select:
        aliases: ['vrf-select']
        type: int
        description: VRF ID used for connection to server.
      log_templates:
        aliases: ['log-templates']
        type: list
        elements: dict
        description: Log templates.
        suboptions:
          category:
            type: str
            description: Category.
            choices: ['app-ctrl', 'attack', 'dlp', 'event', 'traffic', 'virus', 'voip',
                      'webfilter', 'spam', 'anomaly', 'waf', 'dns', 'ssh', 'ssl', 'file-filter',
                      'icap', 'virtual-patch']
          empty_value_indicator:
            aliases: ['empty-value-indicator']
            type: str
            description: Empty value indicator.
          id:
            type: int
            description: Id.
          template:
            type: str
            description: Template.
      reliable:
        type: str
        description: Enable/disable reliable logging
        choices: ['disable', 'enable']
      custom_log_format:
        aliases: ['custom-log-format']
        type: list
        elements: str
        description: Customized format for logs.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Global settings for remote syslog server.
      fortinet.fmgdevice.fmgd_log_syslogd_setting:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        log_syslogd_setting:
          # certificate: <list or string>
          # custom_field_name:
          #   - custom: <string>
          #     id: <integer>
          #     name: <string>
          # enc_algorithm: <value in [high, low, disable, ...]>
          # facility: <value in [kernel, user, mail, ...]>
          # format: <value in [default, csv, cef, ...]>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # max_log_rate: <integer>
          # mode: <value in [udp, legacy-reliable, reliable]>
          # port: <integer>
          # priority: <value in [low, default]>
          # server: <string>
          # ssl_min_proto_version: <value in [default, TLSv1-1, TLSv1-2, ...]>
          # status: <value in [disable, enable]>
          # source_ip: <string>
          # source_ip_interface: <list or string>
          # vrf_select: <integer>
          # log_templates:
          #   - category: <value in [app-ctrl, attack, dlp, ...]>
          #     empty_value_indicator: <string>
          #     id: <integer>
          #     template: <string>
          # reliable: <value in [disable, enable]>
          # custom_log_format: <list or string>
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
        '/pm/config/device/{device}/global/log/syslogd/setting'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'log_syslogd_setting': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'certificate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'custom-field-name': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'custom': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'enc-algorithm': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['high', 'low', 'disable', 'high-medium'], 'type': 'str'},
                'facility': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': [
                        'kernel', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert',
                        'clock', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'
                    ],
                    'type': 'str'
                },
                'format': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['default', 'csv', 'cef', 'rfc5424', 'json', 'custom'],
                    'type': 'str'
                },
                'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'max-log-rate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['udp', 'legacy-reliable', 'reliable'], 'type': 'str'},
                'port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['low', 'default'], 'type': 'str'},
                'server': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'ssl-min-proto-version': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['default', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1', 'TLSv1-3'],
                    'type': 'str'
                },
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'source-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'source-ip-interface': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'log-templates': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'category': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': [
                                'app-ctrl', 'attack', 'dlp', 'event', 'traffic', 'virus', 'voip', 'webfilter', 'spam', 'anomaly', 'waf', 'dns', 'ssh',
                                'ssl', 'file-filter', 'icap', 'virtual-patch'
                            ],
                            'type': 'str'
                        },
                        'empty-value-indicator': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'template': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'reliable': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'custom-log-format': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'log_syslogd_setting'),
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
