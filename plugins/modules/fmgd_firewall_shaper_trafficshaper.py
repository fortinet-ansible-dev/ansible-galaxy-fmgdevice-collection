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
module: fmgd_firewall_shaper_trafficshaper
short_description: Configure shared traffic shaper.
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
    firewall_shaper_trafficshaper:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            bandwidth_unit:
                aliases: ['bandwidth-unit']
                type: str
                description: Unit of measurement for guaranteed and maximum bandwidth for this shaper
                choices:
                    - 'kbps'
                    - 'mbps'
                    - 'gbps'
            diffserv:
                type: str
                description: Enable/disable changing the DiffServ setting applied to traffic accepted by this shaper.
                choices:
                    - 'disable'
                    - 'enable'
            diffservcode:
                type: str
                description: DiffServ setting to be applied to traffic accepted by this shaper.
            dscp_marking_method:
                aliases: ['dscp-marking-method']
                type: str
                description: Select DSCP marking method.
                choices:
                    - 'multi-stage'
                    - 'static'
            exceed_bandwidth:
                aliases: ['exceed-bandwidth']
                type: int
                description: Exceed bandwidth used for DSCP/VLAN CoS multi-stage marking.
            exceed_dscp:
                aliases: ['exceed-dscp']
                type: str
                description: DSCP mark for traffic in guaranteed-bandwidth and exceed-bandwidth.
            guaranteed_bandwidth:
                aliases: ['guaranteed-bandwidth']
                type: int
                description: Amount of bandwidth guaranteed for this shaper
            maximum_bandwidth:
                aliases: ['maximum-bandwidth']
                type: int
                description: Upper bandwidth limit enforced by this shaper
            maximum_dscp:
                aliases: ['maximum-dscp']
                type: str
                description: DSCP mark for traffic in exceed-bandwidth and maximum-bandwidth.
            name:
                type: str
                description: Traffic shaper name.
                required: true
            overhead:
                type: int
                description: Per-packet size overhead used in rate computations.
            per_policy:
                aliases: ['per-policy']
                type: str
                description: Enable/disable applying a separate shaper for each policy.
                choices:
                    - 'disable'
                    - 'enable'
            priority:
                type: str
                description: Higher priority traffic is more likely to be forwarded without delays and without compromising the guaranteed bandwidth.
                choices:
                    - 'high'
                    - 'medium'
                    - 'low'
            exceed_cos:
                aliases: ['exceed-cos']
                type: str
                description: VLAN CoS mark for traffic in [guaranteed-bandwidth, exceed-bandwidth].
            cos:
                type: str
                description: VLAN CoS mark.
            maximum_cos:
                aliases: ['maximum-cos']
                type: str
                description: VLAN CoS mark for traffic in [exceed-bandwidth, maximum-bandwidth].
            cos_marking:
                aliases: ['cos-marking']
                type: str
                description: Enable/disable VLAN CoS marking.
                choices:
                    - 'disable'
                    - 'enable'
            cos_marking_method:
                aliases: ['cos-marking-method']
                type: str
                description: Select VLAN CoS marking method.
                choices:
                    - 'multi-stage'
                    - 'static'
            exceed_class_id:
                aliases: ['exceed-class-id']
                type: list
                elements: str
                description: Class ID for traffic in guaranteed-bandwidth and maximum-bandwidth.
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
    - name: Configure shared traffic shaper.
      fortinet.fmgdevice.fmgd_firewall_shaper_trafficshaper:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_shaper_trafficshaper:
          name: "your value" # Required variable, string
          # bandwidth_unit: <value in [kbps, mbps, gbps]>
          # diffserv: <value in [disable, enable]>
          # diffservcode: <string>
          # dscp_marking_method: <value in [multi-stage, static]>
          # exceed_bandwidth: <integer>
          # exceed_dscp: <string>
          # guaranteed_bandwidth: <integer>
          # maximum_bandwidth: <integer>
          # maximum_dscp: <string>
          # overhead: <integer>
          # per_policy: <value in [disable, enable]>
          # priority: <value in [high, medium, low]>
          # exceed_cos: <string>
          # cos: <string>
          # maximum_cos: <string>
          # cos_marking: <value in [disable, enable]>
          # cos_marking_method: <value in [multi-stage, static]>
          # exceed_class_id: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/shaper/traffic-shaper'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_shaper_trafficshaper': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'bandwidth-unit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['kbps', 'mbps', 'gbps'], 'type': 'str'},
                'diffserv': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diffservcode': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'dscp-marking-method': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['multi-stage', 'static'], 'type': 'str'},
                'exceed-bandwidth': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'exceed-dscp': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'guaranteed-bandwidth': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'maximum-bandwidth': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'maximum-dscp': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'overhead': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'per-policy': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'priority': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['high', 'medium', 'low'], 'type': 'str'},
                'exceed-cos': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'cos': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'maximum-cos': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'cos-marking': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cos-marking-method': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['multi-stage', 'static'], 'type': 'str'},
                'exceed-class-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_shaper_trafficshaper'),
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
