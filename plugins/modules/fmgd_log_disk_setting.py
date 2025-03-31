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
module: fmgd_log_disk_setting
short_description: Settings for local disk logging.
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
    log_disk_setting:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            diskfull:
                type: str
                description: Action to take when disk is full.
                choices:
                    - 'overwrite'
                    - 'blocktraffic'
                    - 'nolog'
            dlp_archive_quota:
                aliases: ['dlp-archive-quota']
                type: int
                description: DLP archive quota
            full_final_warning_threshold:
                aliases: ['full-final-warning-threshold']
                type: int
                description: Log full final warning threshold as a percent
            full_first_warning_threshold:
                aliases: ['full-first-warning-threshold']
                type: int
                description: Log full first warning threshold as a percent
            full_second_warning_threshold:
                aliases: ['full-second-warning-threshold']
                type: int
                description: Log full second warning threshold as a percent
            interface:
                type: list
                elements: str
                description: Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            ips_archive:
                aliases: ['ips-archive']
                type: str
                description: Enable/disable IPS packet archiving to the local disk.
                choices:
                    - 'disable'
                    - 'enable'
            log_quota:
                aliases: ['log-quota']
                type: int
                description: Disk log quota
            max_log_file_size:
                aliases: ['max-log-file-size']
                type: int
                description: Maximum log file size before rolling
            max_policy_packet_capture_size:
                aliases: ['max-policy-packet-capture-size']
                type: int
                description: Maximum size of policy sniffer in MB
            maximum_log_age:
                aliases: ['maximum-log-age']
                type: int
                description: Delete log files older than
            report_quota:
                aliases: ['report-quota']
                type: int
                description: Report db quota
            roll_day:
                aliases: ['roll-day']
                type: list
                elements: str
                description: Day of week on which to roll log file.
                choices:
                    - 'sunday'
                    - 'monday'
                    - 'tuesday'
                    - 'wednesday'
                    - 'thursday'
                    - 'friday'
                    - 'saturday'
            roll_schedule:
                aliases: ['roll-schedule']
                type: str
                description: Frequency to check log file for rolling.
                choices:
                    - 'daily'
                    - 'weekly'
            roll_time:
                aliases: ['roll-time']
                type: str
                description: Time of day to roll the log file
            source_ip:
                aliases: ['source-ip']
                type: str
                description: Source IP address to use for uploading disk log files.
            status:
                type: str
                description: Enable/disable local disk logging.
                choices:
                    - 'disable'
                    - 'enable'
            upload:
                type: str
                description: Enable/disable uploading log files when they are rolled.
                choices:
                    - 'disable'
                    - 'enable'
            upload_delete_files:
                aliases: ['upload-delete-files']
                type: str
                description: Delete log files after uploading
                choices:
                    - 'disable'
                    - 'enable'
            upload_destination:
                aliases: ['upload-destination']
                type: str
                description: The type of server to upload log files to.
                choices:
                    - 'ftp-server'
                    - 'fortianalyzer'
            upload_ssl_conn:
                aliases: ['upload-ssl-conn']
                type: str
                description: Enable/disable encrypted FTPS communication to upload log files.
                choices:
                    - 'default'
                    - 'high'
                    - 'low'
                    - 'disable'
            uploaddir:
                type: str
                description: The remote directory on the FTP server to upload log files to.
            uploadip:
                type: str
                description: IP address of the FTP server to upload log files to.
            uploadpass:
                type: list
                elements: str
                description: Password required to log into the FTP server to upload disk log files.
            uploadport:
                type: int
                description: TCP port to use for communicating with the FTP server
            uploadsched:
                type: str
                description: Set the schedule for uploading log files to the FTP server
                choices:
                    - 'disable'
                    - 'enable'
            uploadtime:
                type: int
                description: Time of day at which log files are uploaded if uploadsched is enabled
            uploadtype:
                type: list
                elements: str
                description: Types of log files to upload.
                choices:
                    - 'traffic'
                    - 'event'
                    - 'virus'
                    - 'webfilter'
                    - 'attack'
                    - 'spamfilter'
                    - 'voip'
                    - 'dlp'
                    - 'app-ctrl'
                    - 'netscan'
                    - 'dlp-archive'
                    - 'IPS'
                    - 'anomaly'
                    - 'waf'
                    - 'gtp'
                    - 'dns'
                    - 'emailfilter'
                    - 'ssh'
                    - 'ssl'
                    - 'cifs'
                    - 'file-filter'
                    - 'icap'
                    - 'ztna'
                    - 'http'
                    - 'virtual-patch'
            uploaduser:
                type: str
                description: Username required to log into the FTP server to upload disk log files.
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
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
    - name: Settings for local disk logging.
      fortinet.fmgdevice.fmgd_log_disk_setting:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        log_disk_setting:
          # diskfull: <value in [overwrite, blocktraffic, nolog]>
          # dlp_archive_quota: <integer>
          # full_final_warning_threshold: <integer>
          # full_first_warning_threshold: <integer>
          # full_second_warning_threshold: <integer>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # ips_archive: <value in [disable, enable]>
          # log_quota: <integer>
          # max_log_file_size: <integer>
          # max_policy_packet_capture_size: <integer>
          # maximum_log_age: <integer>
          # report_quota: <integer>
          # roll_day:
          #   - "sunday"
          #   - "monday"
          #   - "tuesday"
          #   - "wednesday"
          #   - "thursday"
          #   - "friday"
          #   - "saturday"
          # roll_schedule: <value in [daily, weekly]>
          # roll_time: <string>
          # source_ip: <string>
          # status: <value in [disable, enable]>
          # upload: <value in [disable, enable]>
          # upload_delete_files: <value in [disable, enable]>
          # upload_destination: <value in [ftp-server, fortianalyzer]>
          # upload_ssl_conn: <value in [default, high, low, ...]>
          # uploaddir: <string>
          # uploadip: <string>
          # uploadpass: <list or string>
          # uploadport: <integer>
          # uploadsched: <value in [disable, enable]>
          # uploadtime: <integer>
          # uploadtype:
          #   - "traffic"
          #   - "event"
          #   - "virus"
          #   - "webfilter"
          #   - "attack"
          #   - "spamfilter"
          #   - "voip"
          #   - "dlp"
          #   - "app-ctrl"
          #   - "netscan"
          #   - "dlp-archive"
          #   - "IPS"
          #   - "anomaly"
          #   - "waf"
          #   - "gtp"
          #   - "dns"
          #   - "emailfilter"
          #   - "ssh"
          #   - "ssl"
          #   - "cifs"
          #   - "file-filter"
          #   - "icap"
          #   - "ztna"
          #   - "http"
          #   - "virtual-patch"
          # uploaduser: <string>
          # vrf_select: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/log/disk/setting'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'log_disk_setting': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'diskfull': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['overwrite', 'blocktraffic', 'nolog'], 'type': 'str'},
                'dlp-archive-quota': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'full-final-warning-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'full-first-warning-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'full-second-warning-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'ips-archive': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-quota': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'max-log-file-size': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'max-policy-packet-capture-size': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'maximum-log-age': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'report-quota': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'roll-day': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'],
                    'elements': 'str'
                },
                'roll-schedule': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['daily', 'weekly'], 'type': 'str'},
                'roll-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'source-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'upload': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'upload-delete-files': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'upload-destination': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['ftp-server', 'fortianalyzer'], 'type': 'str'},
                'upload-ssl-conn': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['default', 'high', 'low', 'disable'], 'type': 'str'},
                'uploaddir': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'uploadip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'uploadpass': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'uploadport': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'uploadsched': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uploadtime': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'uploadtype': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'traffic', 'event', 'virus', 'webfilter', 'attack', 'spamfilter', 'voip', 'dlp', 'app-ctrl', 'netscan', 'dlp-archive', 'IPS',
                        'anomaly', 'waf', 'gtp', 'dns', 'emailfilter', 'ssh', 'ssl', 'cifs', 'file-filter', 'icap', 'ztna', 'http', 'virtual-patch'
                    ],
                    'elements': 'str'
                },
                'uploaduser': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'log_disk_setting'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
