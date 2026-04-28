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
module: fmgd_firewall_responseshapingpolicy
short_description: Device vdom firewall response shaping policy
description:
    - This module is able to configure a FortiManager device (FortiProxy).
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
    firewall_responseshapingpolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            class_id:
                aliases: ['class-id']
                type: int
                description: Class id.
            class_id_reverse:
                aliases: ['class-id-reverse']
                type: int
                description: Class id reverse.
            comment:
                type: str
                description: Comment.
            dstaddr:
                type: list
                elements: str
                description: Dstaddr.
            dstaddr6:
                type: list
                elements: str
                description: Dstaddr6.
            id:
                type: int
                description: Id.
                required: true
            ip_version:
                aliases: ['ip-version']
                type: str
                description: Ip version.
                choices:
                    - '6'
                    - '4'
            name:
                type: str
                description: Name.
            per_ip_shaper:
                aliases: ['per-ip-shaper']
                type: list
                elements: str
                description: Per ip shaper.
            schedule:
                type: list
                elements: str
                description: Schedule.
            srcaddr:
                type: list
                elements: str
                description: Srcaddr.
            status:
                type: str
                description: Status.
                choices:
                    - 'disable'
                    - 'enable'
            traffic_shaper:
                aliases: ['traffic-shaper']
                type: list
                elements: str
                description: Traffic shaper.
            traffic_shaper_reverse:
                aliases: ['traffic-shaper-reverse']
                type: list
                elements: str
                description: Traffic shaper reverse.
            uuid:
                type: str
                description: Uuid.
            diffserv_forward:
                aliases: ['diffserv-forward']
                type: str
                description: Diffserv forward.
                choices:
                    - 'disable'
                    - 'enable'
            diffserv_reverse:
                aliases: ['diffserv-reverse']
                type: str
                description: Diffserv reverse.
                choices:
                    - 'disable'
                    - 'enable'
            diffservcode_forward:
                aliases: ['diffservcode-forward']
                type: str
                description: Diffservcode forward.
            diffservcode_rev:
                aliases: ['diffservcode-rev']
                type: str
                description: Diffservcode rev.
            matched_shaping_policies:
                aliases: ['matched-shaping-policies']
                type: list
                elements: str
                description: Matched shaping policies.
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
    - name: Device vdom firewall response shaping policy
      fortinet.fmgdevice.fmgd_firewall_responseshapingpolicy:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_responseshapingpolicy:
          id: 0 # Required variable, integer
          # class_id: <integer>
          # class_id_reverse: <integer>
          # comment: <string>
          # dstaddr: <list or string>
          # dstaddr6: <list or string>
          # ip_version: <value in [6, 4]>
          # name: <string>
          # per_ip_shaper: <list or string>
          # schedule: <list or string>
          # srcaddr: <list or string>
          # status: <value in [disable, enable]>
          # traffic_shaper: <list or string>
          # traffic_shaper_reverse: <list or string>
          # uuid: <string>
          # diffserv_forward: <value in [disable, enable]>
          # diffserv_reverse: <value in [disable, enable]>
          # diffservcode_forward: <string>
          # diffservcode_rev: <string>
          # matched_shaping_policies: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/response-shaping-policy'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'id'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_responseshapingpolicy': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'class-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'class-id-reverse': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'comment': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'dstaddr': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dstaddr6': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'ip-version': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['6', '4'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'per-ip-shaper': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'schedule': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'srcaddr': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'traffic-shaper': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'traffic-shaper-reverse': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'uuid': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'diffserv-forward': {'v_range': [['7.4.9', '7.4.10'], ['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diffserv-reverse': {'v_range': [['7.4.9', '7.4.10'], ['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diffservcode-forward': {'v_range': [['7.4.9', '7.4.10'], ['7.6.5', '']], 'type': 'str'},
                'diffservcode-rev': {'v_range': [['7.4.9', '7.4.10'], ['7.6.5', '']], 'type': 'str'},
                'matched-shaping-policies': {'v_range': [['7.4.9', '7.4.10'], ['7.6.5', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_responseshapingpolicy'),
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
