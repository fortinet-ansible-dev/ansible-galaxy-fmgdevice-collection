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
module: fmgd_system_automationaction
short_description: Action for automation stitches.
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
    system_automationaction:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            accprofile:
                type: list
                elements: str
                description: Access profile for CLI script action to access FortiGate features.
            action_type:
                aliases: ['action-type']
                type: str
                description: Action type.
                choices:
                    - 'email'
                    - 'ios-notification'
                    - 'alert'
                    - 'disable-ssid'
                    - 'quarantine'
                    - 'ban-ip'
                    - 'quarantine-forticlient'
                    - 'aws-lambda'
                    - 'webhook'
                    - 'quarantine-nsx'
                    - 'azure-function'
                    - 'cli-script'
                    - 'google-cloud-function'
                    - 'alicloud-function'
                    - 'slack-notification'
                    - 'quarantine-fortinac'
                    - 'microsoft-teams-notification'
                    - 'fortiexplorer-notification'
                    - 'system-actions'
                    - 'diagnose-script'
                    - 'regular-expression'
            alicloud_access_key_id:
                aliases: ['alicloud-access-key-id']
                type: str
                description: AliCloud AccessKey ID.
            alicloud_access_key_secret:
                aliases: ['alicloud-access-key-secret']
                type: list
                elements: str
                description: AliCloud AccessKey secret.
            alicloud_function_authorization:
                aliases: ['alicloud-function-authorization']
                type: str
                description: AliCloud function authorization type.
                choices:
                    - 'anonymous'
                    - 'function'
            aws_api_key:
                aliases: ['aws-api-key']
                type: list
                elements: str
                description: AWS API Gateway API key.
            azure_api_key:
                aliases: ['azure-api-key']
                type: list
                elements: str
                description: Azure function API key.
            azure_function_authorization:
                aliases: ['azure-function-authorization']
                type: str
                description: Azure function authorization level.
                choices:
                    - 'anonymous'
                    - 'function'
                    - 'admin'
            description:
                type: str
                description: Description.
            email_from:
                aliases: ['email-from']
                type: str
                description: Email sender name.
            email_subject:
                aliases: ['email-subject']
                type: str
                description: Email subject.
            email_to:
                aliases: ['email-to']
                type: list
                elements: str
                description: Email addresses.
            execute_security_fabric:
                aliases: ['execute-security-fabric']
                type: str
                description: Enable/disable execution of CLI script on all or only one FortiGate unit in the Security Fabric.
                choices:
                    - 'disable'
                    - 'enable'
            forticare_email:
                aliases: ['forticare-email']
                type: str
                description: Enable/disable use of your FortiCare email address as the email-to address.
                choices:
                    - 'disable'
                    - 'enable'
            http_body:
                aliases: ['http-body']
                type: str
                description: Request body
            http_headers:
                aliases: ['http-headers']
                type: list
                elements: dict
                description: Http headers.
                suboptions:
                    id:
                        type: int
                        description: Entry ID.
                    key:
                        type: str
                        description: Request header key.
                    value:
                        type: str
                        description: Request header value.
            fmgr_message:
                type: str
                description: Message content.
            message_type:
                aliases: ['message-type']
                type: str
                description: Message type.
                choices:
                    - 'text'
                    - 'json'
            method:
                type: str
                description: Request method
                choices:
                    - 'delete'
                    - 'get'
                    - 'post'
                    - 'put'
                    - 'patch'
            minimum_interval:
                aliases: ['minimum-interval']
                type: int
                description: Limit execution to no more than once in this interval
            name:
                type: str
                description: Name.
                required: true
            output_size:
                aliases: ['output-size']
                type: int
                description: Number of megabytes to limit script output to
            port:
                type: int
                description: Protocol port.
            protocol:
                type: str
                description: Request protocol.
                choices:
                    - 'http'
                    - 'https'
            replacement_message:
                aliases: ['replacement-message']
                type: str
                description: Enable/disable replacement message.
                choices:
                    - 'disable'
                    - 'enable'
            replacemsg_group:
                aliases: ['replacemsg-group']
                type: list
                elements: str
                description: Replacement message group.
            script:
                type: str
                description: CLI script.
            sdn_connector:
                aliases: ['sdn-connector']
                type: list
                elements: str
                description: NSX SDN connector names.
            security_tag:
                aliases: ['security-tag']
                type: str
                description: NSX security tag.
            system_action:
                aliases: ['system-action']
                type: str
                description: System action type.
                choices:
                    - 'reboot'
                    - 'shutdown'
                    - 'backup-config'
            timeout:
                type: int
                description: Maximum running time for this script in seconds
            tls_certificate:
                aliases: ['tls-certificate']
                type: list
                elements: str
                description: Custom TLS certificate for API request.
            uri:
                type: str
                description: Request API URI.
            verify_host_cert:
                aliases: ['verify-host-cert']
                type: str
                description: Enable/disable verification of the remote host certificate.
                choices:
                    - 'disable'
                    - 'enable'
            headers:
                type: list
                elements: str
                description: Request headers.
            required:
                type: str
                description: Required in action chain.
                choices:
                    - 'disable'
                    - 'enable'
            delay:
                type: int
                description: Delay before execution
            azure_app:
                aliases: ['azure-app']
                type: str
                description: Azure function application name.
            azure_function:
                aliases: ['azure-function']
                type: str
                description: Azure function name.
            aws_api_path:
                aliases: ['aws-api-path']
                type: str
                description: AWS API Gateway path.
            aws_region:
                aliases: ['aws-region']
                type: str
                description: AWS region.
            gcp_function_domain:
                aliases: ['gcp-function-domain']
                type: str
                description: Google Cloud function domain.
            alicloud_account_id:
                aliases: ['alicloud-account-id']
                type: str
                description: AliCloud account ID.
            alicloud_version:
                aliases: ['alicloud-version']
                type: str
                description: AliCloud version.
            azure_domain:
                aliases: ['azure-domain']
                type: str
                description: Azure function domain.
            aws_api_stage:
                aliases: ['aws-api-stage']
                type: str
                description: AWS API Gateway deployment stage name.
            alicloud_region:
                aliases: ['alicloud-region']
                type: str
                description: AliCloud region.
            gcp_function_region:
                aliases: ['gcp-function-region']
                type: str
                description: Google Cloud function region.
            aws_api_id:
                aliases: ['aws-api-id']
                type: str
                description: AWS API Gateway ID.
            alicloud_service:
                aliases: ['alicloud-service']
                type: str
                description: AliCloud service name.
            alicloud_function:
                aliases: ['alicloud-function']
                type: str
                description: AliCloud function name.
            aws_domain:
                aliases: ['aws-domain']
                type: str
                description: AWS domain.
            gcp_project:
                aliases: ['gcp-project']
                type: str
                description: Google Cloud Platform project name.
            gcp_function:
                aliases: ['gcp-function']
                type: str
                description: Google Cloud function name.
            alicloud_function_domain:
                aliases: ['alicloud-function-domain']
                type: str
                description: AliCloud function domain.
            email_body:
                aliases: ['email-body']
                type: str
                description: Email body.
            duration:
                type: int
                description: Maximum running time for this script in seconds.
            regular_expression:
                aliases: ['regular-expression']
                type: str
                description: Regular expression string.
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
    - name: Action for automation stitches.
      fortinet.fmgdevice.fmgd_system_automationaction:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        state: present # <value in [present, absent]>
        system_automationaction:
          name: "your value" # Required variable, string
          # accprofile: <list or string>
          # action_type: <value in [email, ios-notification, alert, ...]>
          # alicloud_access_key_id: <string>
          # alicloud_access_key_secret: <list or string>
          # alicloud_function_authorization: <value in [anonymous, function]>
          # aws_api_key: <list or string>
          # azure_api_key: <list or string>
          # azure_function_authorization: <value in [anonymous, function, admin]>
          # description: <string>
          # email_from: <string>
          # email_subject: <string>
          # email_to: <list or string>
          # execute_security_fabric: <value in [disable, enable]>
          # forticare_email: <value in [disable, enable]>
          # http_body: <string>
          # http_headers:
          #   - id: <integer>
          #     key: <string>
          #     value: <string>
          # fmgr_message: <string>
          # message_type: <value in [text, json]>
          # method: <value in [delete, get, post, ...]>
          # minimum_interval: <integer>
          # output_size: <integer>
          # port: <integer>
          # protocol: <value in [http, https]>
          # replacement_message: <value in [disable, enable]>
          # replacemsg_group: <list or string>
          # script: <string>
          # sdn_connector: <list or string>
          # security_tag: <string>
          # system_action: <value in [reboot, shutdown, backup-config]>
          # timeout: <integer>
          # tls_certificate: <list or string>
          # uri: <string>
          # verify_host_cert: <value in [disable, enable]>
          # headers: <list or string>
          # required: <value in [disable, enable]>
          # delay: <integer>
          # azure_app: <string>
          # azure_function: <string>
          # aws_api_path: <string>
          # aws_region: <string>
          # gcp_function_domain: <string>
          # alicloud_account_id: <string>
          # alicloud_version: <string>
          # azure_domain: <string>
          # aws_api_stage: <string>
          # alicloud_region: <string>
          # gcp_function_region: <string>
          # aws_api_id: <string>
          # alicloud_service: <string>
          # alicloud_function: <string>
          # aws_domain: <string>
          # gcp_project: <string>
          # gcp_function: <string>
          # alicloud_function_domain: <string>
          # email_body: <string>
          # duration: <integer>
          # regular_expression: <string>
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
        '/pm/config/device/{device}/global/system/automation-action'
    ]
    url_params = ['device']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_automationaction': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'accprofile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'action-type': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'email', 'ios-notification', 'alert', 'disable-ssid', 'quarantine', 'ban-ip', 'quarantine-forticlient', 'aws-lambda', 'webhook',
                        'quarantine-nsx', 'azure-function', 'cli-script', 'google-cloud-function', 'alicloud-function', 'slack-notification',
                        'quarantine-fortinac', 'microsoft-teams-notification', 'fortiexplorer-notification', 'system-actions', 'diagnose-script',
                        'regular-expression'
                    ],
                    'type': 'str'
                },
                'alicloud-access-key-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'str'},
                'alicloud-access-key-secret': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'alicloud-function-authorization': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['anonymous', 'function'], 'type': 'str'},
                'aws-api-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'azure-api-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'azure-function-authorization': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['anonymous', 'function', 'admin'],
                    'type': 'str'
                },
                'description': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'email-from': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'email-subject': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'email-to': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'execute-security-fabric': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'forticare-email': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-body': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'http-headers': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'str'},
                        'value': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'fmgr_message': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'message-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['text', 'json'], 'type': 'str'},
                'method': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['delete', 'get', 'post', 'put', 'patch'], 'type': 'str'},
                'minimum-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'output-size': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'protocol': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['http', 'https'], 'type': 'str'},
                'replacement-message': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'replacemsg-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'script': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'sdn-connector': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'security-tag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'system-action': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['reboot', 'shutdown', 'backup-config'], 'type': 'str'},
                'timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'tls-certificate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'uri': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'verify-host-cert': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'headers': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'required': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'delay': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'azure-app': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'azure-function': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'aws-api-path': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'aws-region': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'gcp-function-domain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'alicloud-account-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'alicloud-version': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'azure-domain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'aws-api-stage': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'alicloud-region': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'gcp-function-region': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'aws-api-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'alicloud-service': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'alicloud-function': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'aws-domain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'gcp-project': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'gcp-function': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'alicloud-function-domain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'email-body': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'duration': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'regular-expression': {'v_range': [['7.6.2', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_automationaction'),
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
