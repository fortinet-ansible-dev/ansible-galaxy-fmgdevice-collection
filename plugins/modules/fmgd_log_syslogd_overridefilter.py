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
module: fmgd_log_syslogd_overridefilter
short_description: Override filters for remote system server.
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
  log_syslogd_overridefilter:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      anomaly:
        type: str
        description: Enable/disable anomaly logging.
        choices: ['disable', 'enable']
      forti_switch:
        aliases: ['forti-switch']
        type: str
        description: Enable/disable Forti-Switch logging.
        choices: ['disable', 'enable']
      forward_traffic:
        aliases: ['forward-traffic']
        type: str
        description: Enable/disable forward traffic logging.
        choices: ['disable', 'enable']
      free_style:
        aliases: ['free-style']
        type: list
        elements: dict
        description: Free style.
        suboptions:
          category:
            type: str
            description: Log category.
            choices: ['traffic', 'event', 'virus', 'webfilter', 'attack', 'spam', 'voip', 'dlp',
                      'app-ctrl', 'anomaly', 'waf', 'gtp', 'dns', 'ssh', 'ssl', 'file-filter',
                      'icap', 'ztna', 'virtual-patch', 'debug']
          filter:
            type: str
            description: Free style filter string.
          filter_type:
            aliases: ['filter-type']
            type: str
            description: Include/exclude logs that match the filter.
            choices: ['include', 'exclude']
          id:
            type: int
            description: Entry ID.
      gtp:
        type: str
        description: Enable/disable GTP messages logging.
        choices: ['disable', 'enable']
      local_traffic:
        aliases: ['local-traffic']
        type: str
        description: Enable/disable local in or out traffic logging.
        choices: ['disable', 'enable']
      multicast_traffic:
        aliases: ['multicast-traffic']
        type: str
        description: Enable/disable multicast traffic logging.
        choices: ['disable', 'enable']
      severity:
        type: str
        description: Lowest severity level to log.
        choices: ['emergency', 'alert', 'critical', 'error', 'warning', 'notification',
                  'information', 'debug']
      sniffer_traffic:
        aliases: ['sniffer-traffic']
        type: str
        description: Enable/disable sniffer traffic logging.
        choices: ['disable', 'enable']
      voip:
        type: str
        description: Enable/disable VoIP logging.
        choices: ['disable', 'enable']
      ztna_traffic:
        aliases: ['ztna-traffic']
        type: str
        description: Enable/disable ztna traffic logging.
        choices: ['disable', 'enable']
      filter_type:
        aliases: ['filter-type']
        type: str
        description: Include/exclude logs that match the filter.
        choices: ['include', 'exclude']
      filter:
        type: str
        description: Syslog filter.
      http_transaction:
        aliases: ['http-transaction']
        type: str
        description: Enable/disable log HTTP transaction messages.
        choices: ['disable', 'enable']
      debug:
        type: str
        description: Enable/disable debug logging.
        choices: ['disable', 'enable']
      ssh:
        type: str
        description: Enable/disable SSH logging.
        choices: ['disable', 'enable']
      dns:
        type: str
        description: Enable/disable detailed DNS event logging.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Override filters for remote system server.
      fortinet.fmgdevice.fmgd_log_syslogd_overridefilter:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        log_syslogd_overridefilter:
          # anomaly: <value in [disable, enable]>
          # forti_switch: <value in [disable, enable]>
          # forward_traffic: <value in [disable, enable]>
          # free_style:
          #   - category: <value in [traffic, event, virus, ...]>
          #     filter: <string>
          #     filter_type: <value in [include, exclude]>
          #     id: <integer>
          # gtp: <value in [disable, enable]>
          # local_traffic: <value in [disable, enable]>
          # multicast_traffic: <value in [disable, enable]>
          # severity: <value in [emergency, alert, critical, ...]>
          # sniffer_traffic: <value in [disable, enable]>
          # voip: <value in [disable, enable]>
          # ztna_traffic: <value in [disable, enable]>
          # filter_type: <value in [include, exclude]>
          # filter: <string>
          # http_transaction: <value in [disable, enable]>
          # debug: <value in [disable, enable]>
          # ssh: <value in [disable, enable]>
          # dns: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/log/syslogd/override-filter'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'log_syslogd_overridefilter': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'anomaly': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'forti-switch': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'forward-traffic': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'free-style': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'category': {
                            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                            'choices': [
                                'traffic', 'event', 'virus', 'webfilter', 'attack', 'spam', 'voip', 'dlp', 'app-ctrl', 'anomaly', 'waf', 'gtp', 'dns',
                                'ssh', 'ssl', 'file-filter', 'icap', 'ztna', 'virtual-patch', 'debug'
                            ],
                            'type': 'str'
                        },
                        'filter': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'filter-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'gtp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-traffic': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'multicast-traffic': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'severity': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                    'type': 'str'
                },
                'sniffer-traffic': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'voip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ztna-traffic': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'filter-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'choices': ['include', 'exclude'], 'type': 'str'},
                'filter': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                'http-transaction': {'v_range': [['7.4.8', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'debug': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssh': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dns': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'log_syslogd_overridefilter'),
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
