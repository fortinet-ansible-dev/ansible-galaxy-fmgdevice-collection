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
module: fmgd_system_icond
short_description: Configure Industrial Connectivity.
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
    system_icond:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            iec101_keepalive:
                aliases: ['iec101-keepalive']
                type: str
                description: Send periodic test frame for probing link status.
                choices:
                    - 'disable'
                    - 'enable'
            iec101_laddr_local:
                aliases: ['iec101-laddr-local']
                type: int
                description: Link address of local.
            iec101_laddr_remote:
                aliases: ['iec101-laddr-remote']
                type: int
                description: Link address of remote.
            iec101_laddr_size:
                aliases: ['iec101-laddr-size']
                type: int
                description: Link address size.
            iec101_mode:
                aliases: ['iec101-mode']
                type: str
                description: Link layer transmission procedure.
                choices:
                    - 'balanced'
                    - 'unbalanced'
            iec101_t0:
                aliases: ['iec101-t0']
                type: int
                description: Time out for repetition of frames in milliseconds
            iec101_trp:
                aliases: ['iec101-trp']
                type: int
                description: Time interval during which repetitions are permitted in milliseconds
            iec101_use_ack_char:
                aliases: ['iec101-use-ack-char']
                type: str
                description: Use single character for ACK.
                choices:
                    - 'disable'
                    - 'enable'
            iec104_k:
                aliases: ['iec104-k']
                type: int
                description: Maximum number of outstanding I formate APDUs
            iec104_t1:
                aliases: ['iec104-t1']
                type: int
                description: Time-out of send or test APDUs in seconds
            iec104_t2:
                aliases: ['iec104-t2']
                type: int
                description: Time-out for acknowledges in case no data messages in seconds
            iec104_t3:
                aliases: ['iec104-t3']
                type: int
                description: Time-out for sending test frames in case of a long idle state in seconds
            iec104_w:
                aliases: ['iec104-w']
                type: int
                description: Maximum number of latest acknowledge APDUs
            modbus_serial_addr:
                aliases: ['modbus-serial-addr']
                type: int
                description: Serial remote station address.
            modbus_serial_mode:
                aliases: ['modbus-serial-mode']
                type: str
                description: Serial transmission mode.
                choices:
                    - 'RTU'
                    - 'ASCII'
            modbus_serial_timeout_resp:
                aliases: ['modbus-serial-timeout-resp']
                type: int
                description: Time out for serial remote station response in milliseconds
            modbus_tcp_unit_id:
                aliases: ['modbus-tcp-unit-id']
                type: int
                description: TCP MBAP unit identifier.
            port:
                type: int
                description: Listening socket port.
            status:
                type: str
                description: Enable/disable this connection.
                choices:
                    - 'disable'
                    - 'enable'
            tty_baudrate:
                aliases: ['tty-baudrate']
                type: str
                description: TTY baudrate.
                choices:
                    - '200'
                    - '300'
                    - '600'
                    - '1200'
                    - '2400'
                    - '4800'
                    - '9600'
                    - '19200'
                    - '38400'
                    - '115200'
            tty_databits:
                aliases: ['tty-databits']
                type: int
                description: TTY databits.
            tty_device:
                aliases: ['tty-device']
                type: str
                description: TTY device.
            tty_flowcontrol:
                aliases: ['tty-flowcontrol']
                type: str
                description: TTY flowcontrol.
                choices:
                    - 'none'
                    - 'xon-xoff'
                    - 'hw'
            tty_parity:
                aliases: ['tty-parity']
                type: str
                description: TTY parity.
                choices:
                    - 'none'
                    - 'odd'
                    - 'even'
            tty_stopbits:
                aliases: ['tty-stopbits']
                type: int
                description: TTY stopbits.
            type:
                type: str
                description: Connection type.
                choices:
                    - 'iec101-104'
                    - 'modbus-serial-tcp'
                    - 'raw'
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
    - name: Configure Industrial Connectivity.
      fortinet.fmgdevice.fmgd_system_icond:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        system_icond:
          # iec101_keepalive: <value in [disable, enable]>
          # iec101_laddr_local: <integer>
          # iec101_laddr_remote: <integer>
          # iec101_laddr_size: <integer>
          # iec101_mode: <value in [balanced, unbalanced]>
          # iec101_t0: <integer>
          # iec101_trp: <integer>
          # iec101_use_ack_char: <value in [disable, enable]>
          # iec104_k: <integer>
          # iec104_t1: <integer>
          # iec104_t2: <integer>
          # iec104_t3: <integer>
          # iec104_w: <integer>
          # modbus_serial_addr: <integer>
          # modbus_serial_mode: <value in [RTU, ASCII]>
          # modbus_serial_timeout_resp: <integer>
          # modbus_tcp_unit_id: <integer>
          # port: <integer>
          # status: <value in [disable, enable]>
          # tty_baudrate: <value in [200, 300, 600, ...]>
          # tty_databits: <integer>
          # tty_device: <string>
          # tty_flowcontrol: <value in [none, xon-xoff, hw]>
          # tty_parity: <value in [none, odd, even]>
          # tty_stopbits: <integer>
          # type: <value in [iec101-104, modbus-serial-tcp, raw]>
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
        '/pm/config/device/{device}/global/system/icond'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_icond': {
            'type': 'dict',
            'v_range': [['7.4.3', '']],
            'options': {
                'iec101-keepalive': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'iec101-laddr-local': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'iec101-laddr-remote': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'iec101-laddr-size': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'iec101-mode': {'v_range': [['7.4.3', '']], 'choices': ['balanced', 'unbalanced'], 'type': 'str'},
                'iec101-t0': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'iec101-trp': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'iec101-use-ack-char': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'iec104-k': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'iec104-t1': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'iec104-t2': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'iec104-t3': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'iec104-w': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'modbus-serial-addr': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'modbus-serial-mode': {'v_range': [['7.4.3', '']], 'choices': ['RTU', 'ASCII'], 'type': 'str'},
                'modbus-serial-timeout-resp': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'modbus-tcp-unit-id': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'port': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'status': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tty-baudrate': {
                    'v_range': [['7.4.3', '']],
                    'choices': ['200', '300', '600', '1200', '2400', '4800', '9600', '19200', '38400', '115200'],
                    'type': 'str'
                },
                'tty-databits': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'tty-device': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'tty-flowcontrol': {'v_range': [['7.4.3', '']], 'choices': ['none', 'xon-xoff', 'hw'], 'type': 'str'},
                'tty-parity': {'v_range': [['7.4.3', '']], 'choices': ['none', 'odd', 'even'], 'type': 'str'},
                'tty-stopbits': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'type': {'v_range': [['7.4.3', '']], 'choices': ['iec101-104', 'modbus-serial-tcp', 'raw'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_icond'),
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
