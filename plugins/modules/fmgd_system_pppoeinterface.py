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
module: fmgd_system_pppoeinterface
short_description: Configure the PPPoE interfaces.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    device:
        description: The parameter (device) in requested url.
        type: str
        required: true
    vdom:
        description: The parameter (vdom) in requested url.
        type: str
        required: true
    system_pppoeinterface:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ac_name:
                aliases: ['ac-name']
                type: str
                description: PPPoE AC name.
            auth_type:
                aliases: ['auth-type']
                type: str
                description: PPP authentication type to use.
                choices:
                    - 'auto'
                    - 'pap'
                    - 'chap'
                    - 'mschapv1'
                    - 'mschapv2'
            device:
                type: list
                elements: str
                description: Name for the physical interface.
            dial_on_demand:
                aliases: ['dial-on-demand']
                type: str
                description: Enable/disable dial on demand to dial the PPPoE interface when packets are routed to the PPPoE interface.
                choices:
                    - 'disable'
                    - 'enable'
            disc_retry_timeout:
                aliases: ['disc-retry-timeout']
                type: int
                description: PPPoE discovery init timeout value in
            idle_timeout:
                aliases: ['idle-timeout']
                type: int
                description: PPPoE auto disconnect after idle timeout
            ipunnumbered:
                type: str
                description: PPPoE unnumbered IP.
            ipv6:
                type: str
                description: Enable/disable IPv6 Control Protocol
                choices:
                    - 'disable'
                    - 'enable'
            lcp_echo_interval:
                aliases: ['lcp-echo-interval']
                type: int
                description: Time in seconds between PPPoE Link Control Protocol
            lcp_max_echo_fails:
                aliases: ['lcp-max-echo-fails']
                type: int
                description: Maximum missed LCP echo messages before disconnect.
            name:
                type: str
                description: Name of the PPPoE interface.
                required: true
            padt_retry_timeout:
                aliases: ['padt-retry-timeout']
                type: int
                description: PPPoE terminate timeout value in
            password:
                type: list
                elements: str
                description: Enter the password.
            pppoe_unnumbered_negotiate:
                aliases: ['pppoe-unnumbered-negotiate']
                type: str
                description: Enable/disable PPPoE unnumbered negotiation.
                choices:
                    - 'disable'
                    - 'enable'
            service_name:
                aliases: ['service-name']
                type: str
                description: PPPoE service name.
            username:
                type: str
                description: User name.
            pppoe_egress_cos:
                aliases: ['pppoe-egress-cos']
                type: str
                description: CoS in VLAN tag for outgoing PPPoE/PPP packets.
                choices:
                    - 'cos0'
                    - 'cos1'
                    - 'cos2'
                    - 'cos3'
                    - 'cos4'
                    - 'cos5'
                    - 'cos6'
                    - 'cos7'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure the PPPoE interfaces.
      fortinet.fmgdevice.fmgd_system_pppoeinterface:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        system_pppoeinterface:
          name: "your value" # Required variable, string
          # ac_name: <string>
          # auth_type: <value in [auto, pap, chap, ...]>
          # device: <list or string>
          # dial_on_demand: <value in [disable, enable]>
          # disc_retry_timeout: <integer>
          # idle_timeout: <integer>
          # ipunnumbered: <string>
          # ipv6: <value in [disable, enable]>
          # lcp_echo_interval: <integer>
          # lcp_max_echo_fails: <integer>
          # padt_retry_timeout: <integer>
          # password: <list or string>
          # pppoe_unnumbered_negotiate: <value in [disable, enable]>
          # service_name: <string>
          # username: <string>
          # pppoe_egress_cos: <value in [cos0, cos1, cos2, ...]>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/pppoe-interface'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_pppoeinterface': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'ac-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'auth-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['auto', 'pap', 'chap', 'mschapv1', 'mschapv2'], 'type': 'str'},
                'device': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dial-on-demand': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'disc-retry-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'idle-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ipunnumbered': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ipv6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'lcp-echo-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'lcp-max-echo-fails': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'padt-retry-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'pppoe-unnumbered-negotiate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'service-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'username': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'pppoe-egress-cos': {
                    'v_range': [['7.4.4', '']],
                    'choices': ['cos0', 'cos1', 'cos2', 'cos3', 'cos4', 'cos5', 'cos6', 'cos7'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_pppoeinterface'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
