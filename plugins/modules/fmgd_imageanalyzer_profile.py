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
module: fmgd_imageanalyzer_profile
short_description: Device vdom image analyzer profile
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
    imageanalyzer_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            alcohol_block_strictness_level:
                aliases: ['alcohol-block-strictness-level']
                type: int
                description: Alcohol block strictness level.
            alcohol_status:
                aliases: ['alcohol-status']
                type: str
                description: Allow/deny the category image.
                choices:
                    - 'allow'
                    - 'deny'
                    - 'monitor'
            blocked_img_cache:
                aliases: ['blocked-img-cache']
                type: str
                description: Blocked img cache.
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                type: str
                description: Comment.
            drugs_block_strictness_level:
                aliases: ['drugs-block-strictness-level']
                type: int
                description: Drugs block strictness level.
            drugs_status:
                aliases: ['drugs-status']
                type: str
                description: Allow/deny the category image.
                choices:
                    - 'allow'
                    - 'deny'
                    - 'monitor'
            extremism_block_strictness_level:
                aliases: ['extremism-block-strictness-level']
                type: int
                description: Extremism block strictness level.
            extremism_status:
                aliases: ['extremism-status']
                type: str
                description: Allow/deny the category image.
                choices:
                    - 'allow'
                    - 'deny'
                    - 'monitor'
            gambling_block_strictness_level:
                aliases: ['gambling-block-strictness-level']
                type: int
                description: Gambling block strictness level.
            gambling_status:
                aliases: ['gambling-status']
                type: str
                description: Gambling status.
                choices:
                    - 'allow'
                    - 'deny'
                    - 'monitor'
            gore_block_strictness_level:
                aliases: ['gore-block-strictness-level']
                type: int
                description: Gore block strictness level.
            gore_status:
                aliases: ['gore-status']
                type: str
                description: Allow/deny the category image.
                choices:
                    - 'allow'
                    - 'deny'
                    - 'monitor'
            image_skip_height:
                aliases: ['image-skip-height']
                type: int
                description: Image skip height.
            image_skip_size:
                aliases: ['image-skip-size']
                type: int
                description: Image skip rating size
            image_skip_width:
                aliases: ['image-skip-width']
                type: int
                description: Image skip width.
            log_option:
                aliases: ['log-option']
                type: str
                description: Log option.
                choices:
                    - 'all'
                    - 'violation'
            name:
                type: str
                description: Profile name.
                required: true
            ocr_activation_threshold:
                aliases: ['ocr-activation-threshold']
                type: int
                description: Ocr activation threshold.
            optical_character_recognition:
                aliases: ['optical-character-recognition']
                type: str
                description: Optical character recognition.
                choices:
                    - 'disable'
                    - 'enable'
            porn_block_strictness_level:
                aliases: ['porn-block-strictness-level']
                type: int
                description: Porn block strictness level.
            porn_status:
                aliases: ['porn-status']
                type: str
                description: Allow/deny the category image.
                choices:
                    - 'allow'
                    - 'deny'
                    - 'monitor'
            rating_err_action:
                aliases: ['rating-err-action']
                type: str
                description: Actions when image rating error.
                choices:
                    - 'block'
                    - 'pass'
            replace_image:
                aliases: ['replace-image']
                type: list
                elements: str
                description: Specify replacement image.
            source_url:
                aliases: ['source-url']
                type: str
                description: Source url.
                choices:
                    - 'disable'
                    - 'enable'
            swim_underwear_block_strictness_level:
                aliases: ['swim_underwear-block-strictness-level']
                type: int
                description: Swim underwear block strictness level.
            swim_underwear_status:
                aliases: ['swim_underwear-status']
                type: str
                description: Allow/deny the category image.
                choices:
                    - 'allow'
                    - 'deny'
                    - 'monitor'
            weapons_block_strictness_level:
                aliases: ['weapons-block-strictness-level']
                type: int
                description: Weapons block strictness level.
            weapons_status:
                aliases: ['weapons-status']
                type: str
                description: Allow/deny the category image.
                choices:
                    - 'allow'
                    - 'deny'
                    - 'monitor'
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
    - name: Device vdom image analyzer profile
      fortinet.fmgdevice.fmgd_imageanalyzer_profile:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        imageanalyzer_profile:
          name: "your value" # Required variable, string
          # alcohol_block_strictness_level: <integer>
          # alcohol_status: <value in [allow, deny, monitor]>
          # blocked_img_cache: <value in [disable, enable]>
          # comment: <string>
          # drugs_block_strictness_level: <integer>
          # drugs_status: <value in [allow, deny, monitor]>
          # extremism_block_strictness_level: <integer>
          # extremism_status: <value in [allow, deny, monitor]>
          # gambling_block_strictness_level: <integer>
          # gambling_status: <value in [allow, deny, monitor]>
          # gore_block_strictness_level: <integer>
          # gore_status: <value in [allow, deny, monitor]>
          # image_skip_height: <integer>
          # image_skip_size: <integer>
          # image_skip_width: <integer>
          # log_option: <value in [all, violation]>
          # ocr_activation_threshold: <integer>
          # optical_character_recognition: <value in [disable, enable]>
          # porn_block_strictness_level: <integer>
          # porn_status: <value in [allow, deny, monitor]>
          # rating_err_action: <value in [block, pass]>
          # replace_image: <list or string>
          # source_url: <value in [disable, enable]>
          # swim_underwear_block_strictness_level: <integer>
          # swim_underwear_status: <value in [allow, deny, monitor]>
          # weapons_block_strictness_level: <integer>
          # weapons_status: <value in [allow, deny, monitor]>
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
        '/pm/config/device/{device}/vdom/{vdom}/image-analyzer/profile'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'imageanalyzer_profile': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'alcohol-block-strictness-level': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'alcohol-status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'deny', 'monitor'], 'type': 'str'},
                'blocked-img-cache': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comment': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'drugs-block-strictness-level': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'drugs-status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'deny', 'monitor'], 'type': 'str'},
                'extremism-block-strictness-level': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'extremism-status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'deny', 'monitor'], 'type': 'str'},
                'gambling-block-strictness-level': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'gambling-status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'deny', 'monitor'], 'type': 'str'},
                'gore-block-strictness-level': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'gore-status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'deny', 'monitor'], 'type': 'str'},
                'image-skip-height': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'image-skip-size': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'image-skip-width': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'log-option': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['all', 'violation'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'ocr-activation-threshold': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'optical-character-recognition': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'porn-block-strictness-level': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'porn-status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'deny', 'monitor'], 'type': 'str'},
                'rating-err-action': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['block', 'pass'], 'type': 'str'},
                'replace-image': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'source-url': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'swim_underwear-block-strictness-level': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'swim_underwear-status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'deny', 'monitor'], 'type': 'str'},
                'weapons-block-strictness-level': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'weapons-status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'deny', 'monitor'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'imageanalyzer_profile'),
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
