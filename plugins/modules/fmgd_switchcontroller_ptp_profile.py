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
module: fmgd_switchcontroller_ptp_profile
short_description: Global PTP profile.
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
  switchcontroller_ptp_profile:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      description:
        type: str
        description: Description.
      domain:
        type: int
        description: Configure PTP domain value
      mode:
        type: str
        description: Select PTP mode.
        choices: ['transparent-e2e', 'transparent-p2p']
      name:
        type: str
        description: Profile name.
        required: true
      pdelay_req_interval:
        aliases: ['pdelay-req-interval']
        type: str
        description: Configure PTP peer delay request interval.
        choices: ['1sec', '2sec', '4sec', '8sec', '16sec', '32sec']
      ptp_profile:
        aliases: ['ptp-profile']
        type: str
        description: Configure PTP power profile.
        choices: ['C37.238-2017']
      transport:
        type: str
        description: Configure PTP transport mode.
        choices: ['l2-mcast']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Global PTP profile.
      fortinet.fmgdevice.fmgd_switchcontroller_ptp_profile:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_ptp_profile:
          name: "your value" # Required variable, string
          # description: <string>
          # domain: <integer>
          # mode: <value in [transparent-e2e, transparent-p2p]>
          # pdelay_req_interval: <value in [1sec, 2sec, 4sec, ...]>
          # ptp_profile: <value in [C37.238-2017]>
          # transport: <value in [l2-mcast]>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/ptp/profile'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'switchcontroller_ptp_profile': {
            'type': 'dict', 'v_range': [['7.4.3', '']],
            'options': {
                'description': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'domain': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'mode': {'v_range': [['7.4.3', '']], 'choices': ['transparent-e2e', 'transparent-p2p'], 'type': 'str'},
                'name': {'v_range': [['7.4.3', '']], 'required': True, 'type': 'str'},
                'pdelay-req-interval': {'v_range': [['7.4.3', '']], 'choices': ['1sec', '2sec', '4sec', '8sec', '16sec', '32sec'], 'type': 'str'},
                'ptp-profile': {'v_range': [['7.4.3', '']], 'choices': ['C37.238-2017'], 'type': 'str'},
                'transport': {'v_range': [['7.4.3', '']], 'choices': ['l2-mcast'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_ptp_profile'),
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
