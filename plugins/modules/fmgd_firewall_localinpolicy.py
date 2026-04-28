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
module: fmgd_firewall_localinpolicy
short_description: Configure user defined IPv4 local-in policies.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
version_added: "1.1.0"
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
    firewall_localinpolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Action performed on traffic matching the policy
                choices:
                    - 'deny'
                    - 'accept'
            comments:
                type: str
                description: Comment.
            dstaddr:
                type: list
                elements: str
                description: Destination address object from available options.
            dstaddr_negate:
                aliases: ['dstaddr-negate']
                type: str
                description: When enabled dstaddr specifies what the destination address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            ha_mgmt_intf_only:
                aliases: ['ha-mgmt-intf-only']
                type: str
                description: Enable/disable dedicating the HA management interface only for local-in policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_src:
                aliases: ['internet-service-src']
                type: str
                description: Enable/disable use of Internet Services in source for this local-in policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_src_custom:
                aliases: ['internet-service-src-custom']
                type: list
                elements: str
                description: Custom Internet Service source name.
            internet_service_src_custom_group:
                aliases: ['internet-service-src-custom-group']
                type: list
                elements: str
                description: Custom Internet Service source group name.
            internet_service_src_group:
                aliases: ['internet-service-src-group']
                type: list
                elements: str
                description: Internet Service source group name.
            internet_service_src_name:
                aliases: ['internet-service-src-name']
                type: list
                elements: str
                description: Internet Service source name.
            internet_service_src_negate:
                aliases: ['internet-service-src-negate']
                type: str
                description: When enabled internet-service-src specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            intf:
                type: list
                elements: str
                description: Incoming interface name from available options.
            policyid:
                type: int
                description: User defined local in policy ID.
                required: true
            schedule:
                type: list
                elements: str
                description: Schedule object from available options.
            service:
                type: list
                elements: str
                description: Service object from available options.
            service_negate:
                aliases: ['service-negate']
                type: str
                description: When enabled service specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            srcaddr:
                type: list
                elements: str
                description: Source address object from available options.
            srcaddr_negate:
                aliases: ['srcaddr-negate']
                type: str
                description: When enabled srcaddr specifies what the source address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            status:
                type: str
                description: Enable/disable this local-in policy.
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: Universally Unique Identifier
            virtual_patch:
                aliases: ['virtual-patch']
                type: str
                description: Enable/disable virtual patching.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_src_fortiguard:
                aliases: ['internet-service-src-fortiguard']
                type: list
                elements: str
                description: FortiGuard Internet Service source name.
            logtraffic:
                type: str
                description: Enable/disable local-in traffic logging.
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure user defined IPv4 local-in policies.
      fortinet.fmgdevice.fmgd_firewall_localinpolicy:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_localinpolicy:
          policyid: 0 # Required variable, integer
          # action: <value in [deny, accept]>
          # comments: <string>
          # dstaddr: <list or string>
          # dstaddr_negate: <value in [disable, enable]>
          # ha_mgmt_intf_only: <value in [disable, enable]>
          # internet_service_src: <value in [disable, enable]>
          # internet_service_src_custom: <list or string>
          # internet_service_src_custom_group: <list or string>
          # internet_service_src_group: <list or string>
          # internet_service_src_name: <list or string>
          # internet_service_src_negate: <value in [disable, enable]>
          # intf: <list or string>
          # schedule: <list or string>
          # service: <list or string>
          # service_negate: <value in [disable, enable]>
          # srcaddr: <list or string>
          # srcaddr_negate: <value in [disable, enable]>
          # status: <value in [disable, enable]>
          # uuid: <string>
          # virtual_patch: <value in [disable, enable]>
          # internet_service_src_fortiguard: <list or string>
          # logtraffic: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/local-in-policy'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'policyid'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_localinpolicy': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'action': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['deny', 'accept'], 'type': 'str'},
                'comments': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'dstaddr': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dstaddr-negate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ha-mgmt-intf-only': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src-custom': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-src-custom-group': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-src-group': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-src-name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-src-negate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'intf': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'policyid': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'schedule': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'service': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'service-negate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcaddr': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'srcaddr-negate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'virtual-patch': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src-fortiguard': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'logtraffic': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_localinpolicy'),
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
