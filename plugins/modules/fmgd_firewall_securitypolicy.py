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
module: fmgd_firewall_securitypolicy
short_description: When configuring policy within policy package, use
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
    firewall_securitypolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _policy_block:
                type: int
                description: Assigned policy block.
            action:
                type: str
                description: Policy action
                choices:
                    - 'deny'
                    - 'accept'
            app_category:
                aliases: ['app-category']
                type: list
                elements: str
                description: Application category ID list.
            app_group:
                aliases: ['app-group']
                type: list
                elements: str
                description: Application group names.
            application:
                type: list
                elements: int
                description: Application ID list.
            application_list:
                aliases: ['application-list']
                type: list
                elements: str
                description: Name of an existing Application list.
            av_profile:
                aliases: ['av-profile']
                type: list
                elements: str
                description: Name of an existing Antivirus profile.
            casb_profile:
                aliases: ['casb-profile']
                type: list
                elements: str
                description: Name of an existing CASB profile.
            comments:
                type: str
                description: Comment.
            diameter_filter_profile:
                aliases: ['diameter-filter-profile']
                type: list
                elements: str
                description: Name of an existing Diameter filter profile.
            dlp_profile:
                aliases: ['dlp-profile']
                type: list
                elements: str
                description: Name of an existing DLP profile.
            dnsfilter_profile:
                aliases: ['dnsfilter-profile']
                type: list
                elements: str
                description: Name of an existing DNS filter profile.
            dstaddr:
                type: list
                elements: str
                description: Destination IPv4 address name and address group names.
            dstaddr_negate:
                aliases: ['dstaddr-negate']
                type: str
                description: When enabled dstaddr specifies what the destination address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr6:
                type: list
                elements: str
                description: Destination IPv6 address name and address group names.
            dstaddr6_negate:
                aliases: ['dstaddr6-negate']
                type: str
                description: When enabled dstaddr6 specifies what the destination address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            dstintf:
                type: list
                elements: str
                description: Outgoing
            emailfilter_profile:
                aliases: ['emailfilter-profile']
                type: list
                elements: str
                description: Name of an existing email filter profile.
            enforce_default_app_port:
                aliases: ['enforce-default-app-port']
                type: str
                description: Enable/disable default application port enforcement for allowed applications.
                choices:
                    - 'disable'
                    - 'enable'
            file_filter_profile:
                aliases: ['file-filter-profile']
                type: list
                elements: str
                description: Name of an existing file-filter profile.
            fsso_groups:
                aliases: ['fsso-groups']
                type: list
                elements: str
                description: Names of FSSO groups.
            global_label:
                aliases: ['global-label']
                type: str
                description: Label for the policy that appears when the GUI is in Global View mode.
            groups:
                type: list
                elements: str
                description: Names of user groups that can authenticate with this policy.
            icap_profile:
                aliases: ['icap-profile']
                type: list
                elements: str
                description: Name of an existing ICAP profile.
            internet_service:
                aliases: ['internet-service']
                type: str
                description: Enable/disable use of Internet Services for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_custom:
                aliases: ['internet-service-custom']
                type: list
                elements: str
                description: Custom Internet Service name.
            internet_service_custom_group:
                aliases: ['internet-service-custom-group']
                type: list
                elements: str
                description: Custom Internet Service group name.
            internet_service_group:
                aliases: ['internet-service-group']
                type: list
                elements: str
                description: Internet Service group name.
            internet_service_name:
                aliases: ['internet-service-name']
                type: list
                elements: str
                description: Internet Service name.
            internet_service_negate:
                aliases: ['internet-service-negate']
                type: str
                description: When enabled internet-service specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_src:
                aliases: ['internet-service-src']
                type: str
                description: Enable/disable use of Internet Services in source for this policy.
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
            internet_service6:
                aliases: ['internet-service6']
                type: str
                description: Enable/disable use of IPv6 Internet Services for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service6_custom:
                aliases: ['internet-service6-custom']
                type: list
                elements: str
                description: Custom IPv6 Internet Service name.
            internet_service6_custom_group:
                aliases: ['internet-service6-custom-group']
                type: list
                elements: str
                description: Custom IPv6 Internet Service group name.
            internet_service6_group:
                aliases: ['internet-service6-group']
                type: list
                elements: str
                description: Internet Service group name.
            internet_service6_name:
                aliases: ['internet-service6-name']
                type: list
                elements: str
                description: IPv6 Internet Service name.
            internet_service6_negate:
                aliases: ['internet-service6-negate']
                type: str
                description: When enabled internet-service6 specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service6_src:
                aliases: ['internet-service6-src']
                type: str
                description: Enable/disable use of IPv6 Internet Services in source for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service6_src_custom:
                aliases: ['internet-service6-src-custom']
                type: list
                elements: str
                description: Custom IPv6 Internet Service source name.
            internet_service6_src_custom_group:
                aliases: ['internet-service6-src-custom-group']
                type: list
                elements: str
                description: Custom Internet Service6 source group name.
            internet_service6_src_group:
                aliases: ['internet-service6-src-group']
                type: list
                elements: str
                description: Internet Service6 source group name.
            internet_service6_src_name:
                aliases: ['internet-service6-src-name']
                type: list
                elements: str
                description: IPv6 Internet Service source name.
            internet_service6_src_negate:
                aliases: ['internet-service6-src-negate']
                type: str
                description: When enabled internet-service6-src specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            ips_sensor:
                aliases: ['ips-sensor']
                type: list
                elements: str
                description: Name of an existing IPS sensor.
            ips_voip_filter:
                aliases: ['ips-voip-filter']
                type: list
                elements: str
                description: Name of an existing VoIP
            learning_mode:
                aliases: ['learning-mode']
                type: str
                description: Enable to allow everything, but log all of the meaningful data for security information gathering.
                choices:
                    - 'disable'
                    - 'enable'
            logtraffic:
                type: str
                description: Enable or disable logging.
                choices:
                    - 'disable'
                    - 'all'
                    - 'utm'
            name:
                type: str
                description: Policy name.
            nat46:
                type: str
                description: Enable/disable NAT46.
                choices:
                    - 'disable'
                    - 'enable'
            nat64:
                type: str
                description: Enable/disable NAT64.
                choices:
                    - 'disable'
                    - 'enable'
            policyid:
                type: int
                description: Policy ID.
                required: true
            profile_group:
                aliases: ['profile-group']
                type: list
                elements: str
                description: Name of profile group.
            profile_protocol_options:
                aliases: ['profile-protocol-options']
                type: list
                elements: str
                description: Name of an existing Protocol options profile.
            profile_type:
                aliases: ['profile-type']
                type: str
                description: Determine whether the firewall policy allows security profile groups or single profiles only.
                choices:
                    - 'single'
                    - 'group'
            schedule:
                type: list
                elements: str
                description: Schedule name.
            sctp_filter_profile:
                aliases: ['sctp-filter-profile']
                type: list
                elements: str
                description: Name of an existing SCTP filter profile.
            send_deny_packet:
                aliases: ['send-deny-packet']
                type: str
                description: Enable to send a reply when a session is denied or blocked by a firewall policy.
                choices:
                    - 'disable'
                    - 'enable'
            service:
                type: list
                elements: str
                description: Service and service group names.
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
                description: Source IPv4 address name and address group names.
            srcaddr_negate:
                aliases: ['srcaddr-negate']
                type: str
                description: When enabled srcaddr specifies what the source address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            srcaddr6:
                type: list
                elements: str
                description: Source IPv6 address name and address group names.
            srcaddr6_negate:
                aliases: ['srcaddr6-negate']
                type: str
                description: When enabled srcaddr6 specifies what the source address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            srcintf:
                type: list
                elements: str
                description: Incoming
            ssh_filter_profile:
                aliases: ['ssh-filter-profile']
                type: list
                elements: str
                description: Name of an existing SSH filter profile.
            ssl_ssh_profile:
                aliases: ['ssl-ssh-profile']
                type: list
                elements: str
                description: Name of an existing SSL SSH profile.
            status:
                type: str
                description: Enable or disable this policy.
                choices:
                    - 'disable'
                    - 'enable'
            url_category:
                aliases: ['url-category']
                type: list
                elements: str
                description: URL categories or groups.
            users:
                type: list
                elements: str
                description: Names of individual users that can authenticate with this policy.
            utm_status:
                aliases: ['utm-status']
                type: str
                description: Enable security profiles.
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: Universally Unique Identifier
            videofilter_profile:
                aliases: ['videofilter-profile']
                type: list
                elements: str
                description: Name of an existing VideoFilter profile.
            virtual_patch_profile:
                aliases: ['virtual-patch-profile']
                type: list
                elements: str
                description: Name of an existing virtual-patch profile.
            voip_profile:
                aliases: ['voip-profile']
                type: list
                elements: str
                description: Name of an existing VoIP
            webfilter_profile:
                aliases: ['webfilter-profile']
                type: list
                elements: str
                description: Name of an existing Web filter profile.
            dlp_sensor:
                aliases: ['dlp-sensor']
                type: list
                elements: str
                description: Name of an existing DLP sensor.
            cifs_profile:
                aliases: ['cifs-profile']
                type: list
                elements: str
                description: Name of an existing CIFS profile.
            logtraffic_start:
                aliases: ['logtraffic-start']
                type: str
                description: Record logs when a session starts.
                choices:
                    - 'disable'
                    - 'enable'
            mms_profile:
                aliases: ['mms-profile']
                type: list
                elements: str
                description: Name of an existing MMS profile.
            internet_service_src_id:
                aliases: ['internet-service-src-id']
                type: list
                elements: str
                description: Internet Service source ID.
            dstaddr4:
                type: list
                elements: str
                description: Destination IPv4 address name and address group names.
            internet_service_id:
                aliases: ['internet-service-id']
                type: list
                elements: str
                description: Internet Service ID.
            srcaddr4:
                type: list
                elements: str
                description: Source IPv4 address name and address group names.
            internet_service_fortiguard:
                aliases: ['internet-service-fortiguard']
                type: list
                elements: str
                description: Internet service fortiguard.
            internet_service_src_fortiguard:
                aliases: ['internet-service-src-fortiguard']
                type: list
                elements: str
                description: Internet service src fortiguard.
            internet_service6_fortiguard:
                aliases: ['internet-service6-fortiguard']
                type: list
                elements: str
                description: Internet service6 fortiguard.
            internet_service6_src_fortiguard:
                aliases: ['internet-service6-src-fortiguard']
                type: list
                elements: str
                description: Internet service6 src fortiguard.
            telemetry_profile:
                aliases: ['telemetry-profile']
                type: list
                elements: str
                description: Name of an existing telemetry profile.
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
    - name: When configuring policy within policy package, use
      fortinet.fmgdevice.fmgd_firewall_securitypolicy:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_securitypolicy:
          policyid: 0 # Required variable, integer
          # _policy_block: <integer>
          # action: <value in [deny, accept]>
          # app_category: <list or string>
          # app_group: <list or string>
          # application: <list or integer>
          # application_list: <list or string>
          # av_profile: <list or string>
          # casb_profile: <list or string>
          # comments: <string>
          # diameter_filter_profile: <list or string>
          # dlp_profile: <list or string>
          # dnsfilter_profile: <list or string>
          # dstaddr: <list or string>
          # dstaddr_negate: <value in [disable, enable]>
          # dstaddr6: <list or string>
          # dstaddr6_negate: <value in [disable, enable]>
          # dstintf: <list or string>
          # emailfilter_profile: <list or string>
          # enforce_default_app_port: <value in [disable, enable]>
          # file_filter_profile: <list or string>
          # fsso_groups: <list or string>
          # global_label: <string>
          # groups: <list or string>
          # icap_profile: <list or string>
          # internet_service: <value in [disable, enable]>
          # internet_service_custom: <list or string>
          # internet_service_custom_group: <list or string>
          # internet_service_group: <list or string>
          # internet_service_name: <list or string>
          # internet_service_negate: <value in [disable, enable]>
          # internet_service_src: <value in [disable, enable]>
          # internet_service_src_custom: <list or string>
          # internet_service_src_custom_group: <list or string>
          # internet_service_src_group: <list or string>
          # internet_service_src_name: <list or string>
          # internet_service_src_negate: <value in [disable, enable]>
          # internet_service6: <value in [disable, enable]>
          # internet_service6_custom: <list or string>
          # internet_service6_custom_group: <list or string>
          # internet_service6_group: <list or string>
          # internet_service6_name: <list or string>
          # internet_service6_negate: <value in [disable, enable]>
          # internet_service6_src: <value in [disable, enable]>
          # internet_service6_src_custom: <list or string>
          # internet_service6_src_custom_group: <list or string>
          # internet_service6_src_group: <list or string>
          # internet_service6_src_name: <list or string>
          # internet_service6_src_negate: <value in [disable, enable]>
          # ips_sensor: <list or string>
          # ips_voip_filter: <list or string>
          # learning_mode: <value in [disable, enable]>
          # logtraffic: <value in [disable, all, utm]>
          # name: <string>
          # nat46: <value in [disable, enable]>
          # nat64: <value in [disable, enable]>
          # profile_group: <list or string>
          # profile_protocol_options: <list or string>
          # profile_type: <value in [single, group]>
          # schedule: <list or string>
          # sctp_filter_profile: <list or string>
          # send_deny_packet: <value in [disable, enable]>
          # service: <list or string>
          # service_negate: <value in [disable, enable]>
          # srcaddr: <list or string>
          # srcaddr_negate: <value in [disable, enable]>
          # srcaddr6: <list or string>
          # srcaddr6_negate: <value in [disable, enable]>
          # srcintf: <list or string>
          # ssh_filter_profile: <list or string>
          # ssl_ssh_profile: <list or string>
          # status: <value in [disable, enable]>
          # url_category: <list or string>
          # users: <list or string>
          # utm_status: <value in [disable, enable]>
          # uuid: <string>
          # videofilter_profile: <list or string>
          # virtual_patch_profile: <list or string>
          # voip_profile: <list or string>
          # webfilter_profile: <list or string>
          # dlp_sensor: <list or string>
          # cifs_profile: <list or string>
          # logtraffic_start: <value in [disable, enable]>
          # mms_profile: <list or string>
          # internet_service_src_id: <list or string>
          # dstaddr4: <list or string>
          # internet_service_id: <list or string>
          # srcaddr4: <list or string>
          # internet_service_fortiguard: <list or string>
          # internet_service_src_fortiguard: <list or string>
          # internet_service6_fortiguard: <list or string>
          # internet_service6_src_fortiguard: <list or string>
          # telemetry_profile: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/security-policy'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'policyid'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_securitypolicy': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                '_policy_block': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'action': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['deny', 'accept'], 'type': 'str'},
                'app-category': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'app-group': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'application': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                'application-list': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'av-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'casb-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'comments': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'diameter-filter-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dlp-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dnsfilter-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dstaddr': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dstaddr-negate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dstaddr6': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dstaddr6-negate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dstintf': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'emailfilter-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'enforce-default-app-port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'file-filter-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'fsso-groups': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'global-label': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'groups': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'icap-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-custom': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-custom-group': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-group': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-negate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src-custom': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-src-custom-group': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-src-group': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-src-name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-src-negate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6-custom': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service6-custom-group': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service6-group': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service6-name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service6-negate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6-src': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6-src-custom': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service6-src-custom-group': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service6-src-group': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service6-src-name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service6-src-negate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ips-sensor': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ips-voip-filter': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'learning-mode': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'logtraffic': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'all', 'utm'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'nat46': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat64': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'policyid': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'profile-group': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'profile-protocol-options': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'profile-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['single', 'group'], 'type': 'str'},
                'schedule': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'sctp-filter-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'send-deny-packet': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'service': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'service-negate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcaddr': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'srcaddr-negate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcaddr6': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'srcaddr6-negate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcintf': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ssh-filter-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ssl-ssh-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'url-category': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'users': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'utm-status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'videofilter-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'virtual-patch-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'voip-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'webfilter-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dlp-sensor': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'cifs-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'logtraffic-start': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mms-profile': {'v_range': [['7.4.8', '7.4.10']], 'type': 'list', 'elements': 'str'},
                'internet-service-src-id': {'v_range': [['7.4.8', '7.4.10']], 'type': 'list', 'elements': 'str'},
                'dstaddr4': {'v_range': [['7.4.8', '7.4.10']], 'type': 'list', 'elements': 'str'},
                'internet-service-id': {'v_range': [['7.4.8', '7.4.10']], 'type': 'list', 'elements': 'str'},
                'srcaddr4': {'v_range': [['7.4.8', '7.4.10']], 'type': 'list', 'elements': 'str'},
                'internet-service-fortiguard': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-src-fortiguard': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service6-fortiguard': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'internet-service6-src-fortiguard': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'telemetry-profile': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_securitypolicy'),
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
