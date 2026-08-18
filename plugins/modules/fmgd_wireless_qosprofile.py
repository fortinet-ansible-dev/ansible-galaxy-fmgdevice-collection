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
module: fmgd_wireless_qosprofile
short_description: Configure WiFi quality of service
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
  wireless_qosprofile:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      bandwidth_admission_control:
        aliases: ['bandwidth-admission-control']
        type: str
        description: Enable/disable WMM bandwidth admission control.
        choices: ['disable', 'enable']
      bandwidth_capacity:
        aliases: ['bandwidth-capacity']
        type: int
        description: Maximum bandwidth capacity allowed
      burst:
        type: str
        description: Enable/disable client rate burst.
        choices: ['disable', 'enable']
      call_admission_control:
        aliases: ['call-admission-control']
        type: str
        description: Enable/disable WMM call admission control.
        choices: ['disable', 'enable']
      call_capacity:
        aliases: ['call-capacity']
        type: int
        description: Maximum number of Voice over WLAN
      comment:
        type: str
        description: Comment.
      downlink:
        type: int
        description: Maximum downlink bandwidth for Virtual Access Points
      downlink_sta:
        aliases: ['downlink-sta']
        type: int
        description: Maximum downlink bandwidth for clients
      dscp_wmm_be:
        aliases: ['dscp-wmm-be']
        type: list
        elements: int
        description: DSCP mapping for best effort access
      dscp_wmm_bk:
        aliases: ['dscp-wmm-bk']
        type: list
        elements: int
        description: DSCP mapping for background access
      dscp_wmm_mapping:
        aliases: ['dscp-wmm-mapping']
        type: str
        description: Enable/disable Differentiated Services Code Point
        choices: ['disable', 'enable']
      dscp_wmm_vi:
        aliases: ['dscp-wmm-vi']
        type: list
        elements: int
        description: DSCP mapping for video access
      dscp_wmm_vo:
        aliases: ['dscp-wmm-vo']
        type: list
        elements: int
        description: DSCP mapping for voice access
      name:
        type: str
        description: WiFi QoS profile name.
        required: true
      uplink:
        type: int
        description: Maximum uplink bandwidth for Virtual Access Points
      uplink_sta:
        aliases: ['uplink-sta']
        type: int
        description: Maximum uplink bandwidth for clients
      wmm:
        type: str
        description: Enable/disable WiFi multi-media
        choices: ['disable', 'enable']
      wmm_be_dscp:
        aliases: ['wmm-be-dscp']
        type: int
        description: DSCP marking for best effort access
      wmm_bk_dscp:
        aliases: ['wmm-bk-dscp']
        type: int
        description: DSCP marking for background access
      wmm_dscp_marking:
        aliases: ['wmm-dscp-marking']
        type: str
        description: Enable/disable WMM Differentiated Services Code Point
        choices: ['disable', 'enable']
      wmm_uapsd:
        aliases: ['wmm-uapsd']
        type: str
        description: Enable/disable WMM Unscheduled Automatic Power Save Delivery
        choices: ['disable', 'enable']
      wmm_vi_dscp:
        aliases: ['wmm-vi-dscp']
        type: int
        description: DSCP marking for video access
      wmm_vo_dscp:
        aliases: ['wmm-vo-dscp']
        type: int
        description: DSCP marking for voice access
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure WiFi quality of service
      fortinet.fmgdevice.fmgd_wireless_qosprofile:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        wireless_qosprofile:
          name: "your value" # Required variable, string
          # bandwidth_admission_control: <value in [disable, enable]>
          # bandwidth_capacity: <integer>
          # burst: <value in [disable, enable]>
          # call_admission_control: <value in [disable, enable]>
          # call_capacity: <integer>
          # comment: <string>
          # downlink: <integer>
          # downlink_sta: <integer>
          # dscp_wmm_be: <list or integer>
          # dscp_wmm_bk: <list or integer>
          # dscp_wmm_mapping: <value in [disable, enable]>
          # dscp_wmm_vi: <list or integer>
          # dscp_wmm_vo: <list or integer>
          # uplink: <integer>
          # uplink_sta: <integer>
          # wmm: <value in [disable, enable]>
          # wmm_be_dscp: <integer>
          # wmm_bk_dscp: <integer>
          # wmm_dscp_marking: <value in [disable, enable]>
          # wmm_uapsd: <value in [disable, enable]>
          # wmm_vi_dscp: <integer>
          # wmm_vo_dscp: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/qos-profile'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wireless_qosprofile': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'bandwidth-admission-control': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bandwidth-capacity': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'burst': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'call-admission-control': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'call-capacity': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'comment': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'downlink': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'downlink-sta': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'dscp-wmm-be': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'dscp-wmm-bk': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'dscp-wmm-mapping': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dscp-wmm-vi': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'dscp-wmm-vo': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'uplink': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'uplink-sta': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'wmm': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wmm-be-dscp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'wmm-bk-dscp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'wmm-dscp-marking': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wmm-uapsd': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wmm-vi-dscp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'wmm-vo-dscp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_qosprofile'),
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
