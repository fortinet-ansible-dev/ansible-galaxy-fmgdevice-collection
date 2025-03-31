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
module: fmgd_wireless_wtp
short_description: Configure Wireless Termination Points
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
    wireless_wtp:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            admin:
                type: str
                description: Configure how the FortiGate operating as a wireless controller discovers and manages this WTP, AP or FortiAP.
                choices:
                    - 'discovery'
                    - 'disable'
                    - 'enable'
                    - 'discovered'
            allowaccess:
                type: list
                elements: str
                description: Control management access to the managed WTP, FortiAP, or AP.
                choices:
                    - 'https'
                    - 'ssh'
                    - 'snmp'
                    - 'http'
                    - 'telnet'
            apcfg_profile:
                aliases: ['apcfg-profile']
                type: list
                elements: str
                description: AP local configuration profile name.
            ble_major_id:
                aliases: ['ble-major-id']
                type: int
                description: Override BLE Major ID.
            ble_minor_id:
                aliases: ['ble-minor-id']
                type: int
                description: Override BLE Minor ID.
            bonjour_profile:
                aliases: ['bonjour-profile']
                type: list
                elements: str
                description: Bonjour profile name.
            coordinate_latitude:
                aliases: ['coordinate-latitude']
                type: str
                description: WTP latitude coordinate.
            coordinate_longitude:
                aliases: ['coordinate-longitude']
                type: str
                description: WTP longitude coordinate.
            firmware_provision:
                aliases: ['firmware-provision']
                type: str
                description: Firmware version to provision to this FortiAP on bootup
            firmware_provision_latest:
                aliases: ['firmware-provision-latest']
                type: str
                description: Enable/disable one-time automatic provisioning of the latest firmware version.
                choices:
                    - 'disable'
                    - 'once'
            image_download:
                aliases: ['image-download']
                type: str
                description: Enable/disable WTP image download.
                choices:
                    - 'disable'
                    - 'enable'
            index:
                type: int
                description: Index.
            ip_fragment_preventing:
                aliases: ['ip-fragment-preventing']
                type: list
                elements: str
                description: Method
                choices:
                    - 'tcp-mss-adjust'
                    - 'icmp-unreachable'
            lan:
                type: dict
                description: Lan.
                suboptions:
                    port_esl_mode:
                        aliases: ['port-esl-mode']
                        type: str
                        description: ESL port mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port_esl_ssid:
                        aliases: ['port-esl-ssid']
                        type: list
                        elements: str
                        description: Bridge ESL port to SSID.
                    port_mode:
                        aliases: ['port-mode']
                        type: str
                        description: LAN port mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port_ssid:
                        aliases: ['port-ssid']
                        type: list
                        elements: str
                        description: Bridge LAN port to SSID.
                    port1_mode:
                        aliases: ['port1-mode']
                        type: str
                        description: LAN port 1 mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port1_ssid:
                        aliases: ['port1-ssid']
                        type: list
                        elements: str
                        description: Bridge LAN port 1 to SSID.
                    port2_mode:
                        aliases: ['port2-mode']
                        type: str
                        description: LAN port 2 mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port2_ssid:
                        aliases: ['port2-ssid']
                        type: list
                        elements: str
                        description: Bridge LAN port 2 to SSID.
                    port3_mode:
                        aliases: ['port3-mode']
                        type: str
                        description: LAN port 3 mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port3_ssid:
                        aliases: ['port3-ssid']
                        type: list
                        elements: str
                        description: Bridge LAN port 3 to SSID.
                    port4_mode:
                        aliases: ['port4-mode']
                        type: str
                        description: LAN port 4 mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port4_ssid:
                        aliases: ['port4-ssid']
                        type: list
                        elements: str
                        description: Bridge LAN port 4 to SSID.
                    port5_mode:
                        aliases: ['port5-mode']
                        type: str
                        description: LAN port 5 mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port5_ssid:
                        aliases: ['port5-ssid']
                        type: list
                        elements: str
                        description: Bridge LAN port 5 to SSID.
                    port6_mode:
                        aliases: ['port6-mode']
                        type: str
                        description: LAN port 6 mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port6_ssid:
                        aliases: ['port6-ssid']
                        type: list
                        elements: str
                        description: Bridge LAN port 6 to SSID.
                    port7_mode:
                        aliases: ['port7-mode']
                        type: str
                        description: LAN port 7 mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port7_ssid:
                        aliases: ['port7-ssid']
                        type: list
                        elements: str
                        description: Bridge LAN port 7 to SSID.
                    port8_mode:
                        aliases: ['port8-mode']
                        type: str
                        description: LAN port 8 mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port8_ssid:
                        aliases: ['port8-ssid']
                        type: list
                        elements: str
                        description: Bridge LAN port 8 to SSID.
            led_state:
                aliases: ['led-state']
                type: str
                description: Enable to allow the FortiAPs LEDs to light.
                choices:
                    - 'disable'
                    - 'enable'
            location:
                type: str
                description: Field for describing the physical location of the WTP, AP or FortiAP.
            login_passwd:
                aliases: ['login-passwd']
                type: list
                elements: str
                description: Set the managed WTP, FortiAP, or APs administrator password.
            login_passwd_change:
                aliases: ['login-passwd-change']
                type: str
                description: Change or reset the administrator password of a managed WTP, FortiAP or AP
                choices:
                    - 'no'
                    - 'yes'
                    - 'default'
            mesh_bridge_enable:
                aliases: ['mesh-bridge-enable']
                type: str
                description: Enable/disable mesh Ethernet bridge when WTP is configured as a mesh branch/leaf AP.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'default'
            name:
                type: str
                description: WTP, AP or FortiAP configuration name.
            override_allowaccess:
                aliases: ['override-allowaccess']
                type: str
                description: Enable to override the WTP profile management access configuration.
                choices:
                    - 'disable'
                    - 'enable'
            override_ip_fragment:
                aliases: ['override-ip-fragment']
                type: str
                description: Enable/disable overriding the WTP profile IP fragment prevention setting.
                choices:
                    - 'disable'
                    - 'enable'
            override_lan:
                aliases: ['override-lan']
                type: str
                description: Enable to override the WTP profile LAN port setting.
                choices:
                    - 'disable'
                    - 'enable'
            override_led_state:
                aliases: ['override-led-state']
                type: str
                description: Enable to override the profile LED state setting for this FortiAP.
                choices:
                    - 'disable'
                    - 'enable'
            override_login_passwd_change:
                aliases: ['override-login-passwd-change']
                type: str
                description: Enable to override the WTP profile login-password
                choices:
                    - 'disable'
                    - 'enable'
            override_split_tunnel:
                aliases: ['override-split-tunnel']
                type: str
                description: Enable/disable overriding the WTP profile split tunneling setting.
                choices:
                    - 'disable'
                    - 'enable'
            override_wan_port_mode:
                aliases: ['override-wan-port-mode']
                type: str
                description: Enable/disable overriding the wan-port-mode in the WTP profile.
                choices:
                    - 'disable'
                    - 'enable'
            purdue_level:
                aliases: ['purdue-level']
                type: str
                description: Purdue Level of this WTP.
                choices:
                    - '1'
                    - '2'
                    - '3'
                    - '4'
                    - '5'
                    - '1.5'
                    - '2.5'
                    - '3.5'
                    - '5.5'
            radio_1:
                aliases: ['radio-1']
                type: dict
                description: Radio 1.
                suboptions:
                    auto_power_high:
                        aliases: ['auto-power-high']
                        type: int
                        description: The upper bound of automatic transmit power adjustment in dBm
                    auto_power_level:
                        aliases: ['auto-power-level']
                        type: str
                        description: Enable/disable automatic power-level adjustment to prevent co-channel interference
                        choices:
                            - 'disable'
                            - 'enable'
                    auto_power_low:
                        aliases: ['auto-power-low']
                        type: int
                        description: The lower bound of automatic transmit power adjustment in dBm
                    auto_power_target:
                        aliases: ['auto-power-target']
                        type: str
                        description: Target of automatic transmit power adjustment in dBm
                    band:
                        type: list
                        elements: str
                        description: WiFi band that Radio 1 operates on.
                        choices:
                            - '802.11a'
                            - '802.11b'
                            - '802.11g'
                            - '802.11n'
                            - '802.11n-5G'
                            - '802.11n,g-only'
                            - '802.11g-only'
                            - '802.11n-only'
                            - '802.11n-5G-only'
                            - '802.11ac'
                            - '802.11ac,n-only'
                            - '802.11ac-only'
                            - '802.11ax-5G'
                            - '802.11ax,ac-only'
                            - '802.11ax,ac,n-only'
                            - '802.11ax-5G-only'
                            - '802.11ax'
                            - '802.11ax,n-only'
                            - '802.11ax,n,g-only'
                            - '802.11ax-only'
                            - '802.11ac-2G'
                            - '802.11ax-6G'
                            - '802.11n-2G'
                            - '802.11ac-5G'
                            - '802.11ax-2G'
                            - '802.11be-2G'
                            - '802.11be-5G'
                            - '802.11be-6G'
                    channel:
                        type: list
                        elements: str
                        description: Selected list of wireless radio channels.
                    drma_manual_mode:
                        aliases: ['drma-manual-mode']
                        type: str
                        description: Radio mode to be used for DRMA manual mode
                        choices:
                            - 'ap'
                            - 'monitor'
                            - 'ncf'
                            - 'ncf-peek'
                    override_band:
                        aliases: ['override-band']
                        type: str
                        description: Enable to override the WTP profile band setting.
                        choices:
                            - 'disable'
                            - 'enable'
                    override_channel:
                        aliases: ['override-channel']
                        type: str
                        description: Enable to override WTP profile channel settings.
                        choices:
                            - 'disable'
                            - 'enable'
                    override_txpower:
                        aliases: ['override-txpower']
                        type: str
                        description: Enable to override the WTP profile power level configuration.
                        choices:
                            - 'disable'
                            - 'enable'
                    override_vaps:
                        aliases: ['override-vaps']
                        type: str
                        description: Enable to override WTP profile Virtual Access Point
                        choices:
                            - 'disable'
                            - 'enable'
                    power_level:
                        aliases: ['power-level']
                        type: int
                        description: Radio EIRP power level as a percentage of the maximum EIRP power
                    power_mode:
                        aliases: ['power-mode']
                        type: str
                        description: Set radio effective isotropic radiated power
                        choices:
                            - 'dBm'
                            - 'percentage'
                    power_value:
                        aliases: ['power-value']
                        type: int
                        description: Radio EIRP power in dBm
                    radio_id:
                        aliases: ['radio-id']
                        type: int
                        description: Radio id.
                    vap_all:
                        aliases: ['vap-all']
                        type: str
                        description: Configure method for assigning SSIDs to this FortiAP
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'tunnel'
                            - 'bridge'
                            - 'manual'
                    vap1:
                        type: str
                        description: Virtual Access Point
                    vap2:
                        type: str
                        description: Virtual Access Point
                    vap3:
                        type: str
                        description: Virtual Access Point
                    vap4:
                        type: str
                        description: Virtual Access Point
                    vap5:
                        type: str
                        description: Virtual Access Point
                    vap6:
                        type: str
                        description: Virtual Access Point
                    vap7:
                        type: str
                        description: Virtual Access Point
                    vap8:
                        type: str
                        description: Virtual Access Point
                    vaps:
                        type: list
                        elements: str
                        description: Manually selected list of Virtual Access Points
                    spectrum_analysis:
                        aliases: ['spectrum-analysis']
                        type: str
                        description: Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'scan-only'
                    override_analysis:
                        aliases: ['override-analysis']
                        type: str
                        description: Enable to override the WTP profile spectrum analysis configuration.
                        choices:
                            - 'disable'
                            - 'enable'
            radio_2:
                aliases: ['radio-2']
                type: dict
                description: Radio 2.
                suboptions:
                    auto_power_high:
                        aliases: ['auto-power-high']
                        type: int
                        description: The upper bound of automatic transmit power adjustment in dBm
                    auto_power_level:
                        aliases: ['auto-power-level']
                        type: str
                        description: Enable/disable automatic power-level adjustment to prevent co-channel interference
                        choices:
                            - 'disable'
                            - 'enable'
                    auto_power_low:
                        aliases: ['auto-power-low']
                        type: int
                        description: The lower bound of automatic transmit power adjustment in dBm
                    auto_power_target:
                        aliases: ['auto-power-target']
                        type: str
                        description: Target of automatic transmit power adjustment in dBm
                    band:
                        type: list
                        elements: str
                        description: WiFi band that Radio 2 operates on.
                        choices:
                            - '802.11a'
                            - '802.11b'
                            - '802.11g'
                            - '802.11n'
                            - '802.11n-5G'
                            - '802.11n,g-only'
                            - '802.11g-only'
                            - '802.11n-only'
                            - '802.11n-5G-only'
                            - '802.11ac'
                            - '802.11ac,n-only'
                            - '802.11ac-only'
                            - '802.11ax-5G'
                            - '802.11ax,ac-only'
                            - '802.11ax,ac,n-only'
                            - '802.11ax-5G-only'
                            - '802.11ax'
                            - '802.11ax,n-only'
                            - '802.11ax,n,g-only'
                            - '802.11ax-only'
                            - '802.11ac-2G'
                            - '802.11ax-6G'
                            - '802.11n-2G'
                            - '802.11ac-5G'
                            - '802.11ax-2G'
                            - '802.11be-2G'
                            - '802.11be-5G'
                            - '802.11be-6G'
                    channel:
                        type: list
                        elements: str
                        description: Selected list of wireless radio channels.
                    drma_manual_mode:
                        aliases: ['drma-manual-mode']
                        type: str
                        description: Radio mode to be used for DRMA manual mode
                        choices:
                            - 'ap'
                            - 'monitor'
                            - 'ncf'
                            - 'ncf-peek'
                    override_band:
                        aliases: ['override-band']
                        type: str
                        description: Enable to override the WTP profile band setting.
                        choices:
                            - 'disable'
                            - 'enable'
                    override_channel:
                        aliases: ['override-channel']
                        type: str
                        description: Enable to override WTP profile channel settings.
                        choices:
                            - 'disable'
                            - 'enable'
                    override_txpower:
                        aliases: ['override-txpower']
                        type: str
                        description: Enable to override the WTP profile power level configuration.
                        choices:
                            - 'disable'
                            - 'enable'
                    override_vaps:
                        aliases: ['override-vaps']
                        type: str
                        description: Enable to override WTP profile Virtual Access Point
                        choices:
                            - 'disable'
                            - 'enable'
                    power_level:
                        aliases: ['power-level']
                        type: int
                        description: Radio EIRP power level as a percentage of the maximum EIRP power
                    power_mode:
                        aliases: ['power-mode']
                        type: str
                        description: Set radio effective isotropic radiated power
                        choices:
                            - 'dBm'
                            - 'percentage'
                    power_value:
                        aliases: ['power-value']
                        type: int
                        description: Radio EIRP power in dBm
                    radio_id:
                        aliases: ['radio-id']
                        type: int
                        description: Radio id.
                    vap_all:
                        aliases: ['vap-all']
                        type: str
                        description: Configure method for assigning SSIDs to this FortiAP
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'tunnel'
                            - 'bridge'
                            - 'manual'
                    vap1:
                        type: str
                        description: Virtual Access Point
                    vap2:
                        type: str
                        description: Virtual Access Point
                    vap3:
                        type: str
                        description: Virtual Access Point
                    vap4:
                        type: str
                        description: Virtual Access Point
                    vap5:
                        type: str
                        description: Virtual Access Point
                    vap6:
                        type: str
                        description: Virtual Access Point
                    vap7:
                        type: str
                        description: Virtual Access Point
                    vap8:
                        type: str
                        description: Virtual Access Point
                    vaps:
                        type: list
                        elements: str
                        description: Manually selected list of Virtual Access Points
                    spectrum_analysis:
                        aliases: ['spectrum-analysis']
                        type: str
                        description: Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'scan-only'
                    override_analysis:
                        aliases: ['override-analysis']
                        type: str
                        description: Enable to override the WTP profile spectrum analysis configuration.
                        choices:
                            - 'disable'
                            - 'enable'
            radio_3:
                aliases: ['radio-3']
                type: dict
                description: Radio 3.
                suboptions:
                    auto_power_high:
                        aliases: ['auto-power-high']
                        type: int
                        description: The upper bound of automatic transmit power adjustment in dBm
                    auto_power_level:
                        aliases: ['auto-power-level']
                        type: str
                        description: Enable/disable automatic power-level adjustment to prevent co-channel interference
                        choices:
                            - 'disable'
                            - 'enable'
                    auto_power_low:
                        aliases: ['auto-power-low']
                        type: int
                        description: The lower bound of automatic transmit power adjustment in dBm
                    auto_power_target:
                        aliases: ['auto-power-target']
                        type: str
                        description: Target of automatic transmit power adjustment in dBm
                    band:
                        type: list
                        elements: str
                        description: WiFi band that Radio 3 operates on.
                        choices:
                            - '802.11a'
                            - '802.11b'
                            - '802.11g'
                            - '802.11n'
                            - '802.11n-5G'
                            - '802.11n,g-only'
                            - '802.11g-only'
                            - '802.11n-only'
                            - '802.11n-5G-only'
                            - '802.11ac'
                            - '802.11ac,n-only'
                            - '802.11ac-only'
                            - '802.11ax-5G'
                            - '802.11ax,ac-only'
                            - '802.11ax,ac,n-only'
                            - '802.11ax-5G-only'
                            - '802.11ax'
                            - '802.11ax,n-only'
                            - '802.11ax,n,g-only'
                            - '802.11ax-only'
                            - '802.11ac-2G'
                            - '802.11ax-6G'
                            - '802.11n-2G'
                            - '802.11ac-5G'
                            - '802.11ax-2G'
                            - '802.11be-2G'
                            - '802.11be-5G'
                            - '802.11be-6G'
                    channel:
                        type: list
                        elements: str
                        description: Selected list of wireless radio channels.
                    drma_manual_mode:
                        aliases: ['drma-manual-mode']
                        type: str
                        description: Radio mode to be used for DRMA manual mode
                        choices:
                            - 'ap'
                            - 'monitor'
                            - 'ncf'
                            - 'ncf-peek'
                    override_band:
                        aliases: ['override-band']
                        type: str
                        description: Enable to override the WTP profile band setting.
                        choices:
                            - 'disable'
                            - 'enable'
                    override_channel:
                        aliases: ['override-channel']
                        type: str
                        description: Enable to override WTP profile channel settings.
                        choices:
                            - 'disable'
                            - 'enable'
                    override_txpower:
                        aliases: ['override-txpower']
                        type: str
                        description: Enable to override the WTP profile power level configuration.
                        choices:
                            - 'disable'
                            - 'enable'
                    override_vaps:
                        aliases: ['override-vaps']
                        type: str
                        description: Enable to override WTP profile Virtual Access Point
                        choices:
                            - 'disable'
                            - 'enable'
                    power_level:
                        aliases: ['power-level']
                        type: int
                        description: Radio EIRP power level as a percentage of the maximum EIRP power
                    power_mode:
                        aliases: ['power-mode']
                        type: str
                        description: Set radio effective isotropic radiated power
                        choices:
                            - 'dBm'
                            - 'percentage'
                    power_value:
                        aliases: ['power-value']
                        type: int
                        description: Radio EIRP power in dBm
                    radio_id:
                        aliases: ['radio-id']
                        type: int
                        description: Radio id.
                    vap_all:
                        aliases: ['vap-all']
                        type: str
                        description: Configure method for assigning SSIDs to this FortiAP
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'tunnel'
                            - 'bridge'
                            - 'manual'
                    vap1:
                        type: str
                        description: Virtual Access Point
                    vap2:
                        type: str
                        description: Virtual Access Point
                    vap3:
                        type: str
                        description: Virtual Access Point
                    vap4:
                        type: str
                        description: Virtual Access Point
                    vap5:
                        type: str
                        description: Virtual Access Point
                    vap6:
                        type: str
                        description: Virtual Access Point
                    vap7:
                        type: str
                        description: Virtual Access Point
                    vap8:
                        type: str
                        description: Virtual Access Point
                    vaps:
                        type: list
                        elements: str
                        description: Manually selected list of Virtual Access Points
                    spectrum_analysis:
                        aliases: ['spectrum-analysis']
                        type: str
                        description: Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'scan-only'
                    override_analysis:
                        aliases: ['override-analysis']
                        type: str
                        description: Enable to override the WTP profile spectrum analysis configuration.
                        choices:
                            - 'disable'
                            - 'enable'
            radio_4:
                aliases: ['radio-4']
                type: dict
                description: Radio 4.
                suboptions:
                    auto_power_high:
                        aliases: ['auto-power-high']
                        type: int
                        description: The upper bound of automatic transmit power adjustment in dBm
                    auto_power_level:
                        aliases: ['auto-power-level']
                        type: str
                        description: Enable/disable automatic power-level adjustment to prevent co-channel interference
                        choices:
                            - 'disable'
                            - 'enable'
                    auto_power_low:
                        aliases: ['auto-power-low']
                        type: int
                        description: The lower bound of automatic transmit power adjustment in dBm
                    auto_power_target:
                        aliases: ['auto-power-target']
                        type: str
                        description: Target of automatic transmit power adjustment in dBm
                    band:
                        type: list
                        elements: str
                        description: WiFi band that Radio 4 operates on.
                        choices:
                            - '802.11a'
                            - '802.11b'
                            - '802.11g'
                            - '802.11n'
                            - '802.11n-5G'
                            - '802.11n,g-only'
                            - '802.11g-only'
                            - '802.11n-only'
                            - '802.11n-5G-only'
                            - '802.11ac'
                            - '802.11ac,n-only'
                            - '802.11ac-only'
                            - '802.11ax-5G'
                            - '802.11ax,ac-only'
                            - '802.11ax,ac,n-only'
                            - '802.11ax-5G-only'
                            - '802.11ax'
                            - '802.11ax,n-only'
                            - '802.11ax,n,g-only'
                            - '802.11ax-only'
                            - '802.11ac-2G'
                            - '802.11ax-6G'
                            - '802.11n-2G'
                            - '802.11ac-5G'
                            - '802.11ax-2G'
                            - '802.11be-2G'
                            - '802.11be-5G'
                            - '802.11be-6G'
                    channel:
                        type: list
                        elements: str
                        description: Selected list of wireless radio channels.
                    drma_manual_mode:
                        aliases: ['drma-manual-mode']
                        type: str
                        description: Radio mode to be used for DRMA manual mode
                        choices:
                            - 'ap'
                            - 'monitor'
                            - 'ncf'
                            - 'ncf-peek'
                    override_band:
                        aliases: ['override-band']
                        type: str
                        description: Enable to override the WTP profile band setting.
                        choices:
                            - 'disable'
                            - 'enable'
                    override_channel:
                        aliases: ['override-channel']
                        type: str
                        description: Enable to override WTP profile channel settings.
                        choices:
                            - 'disable'
                            - 'enable'
                    override_txpower:
                        aliases: ['override-txpower']
                        type: str
                        description: Enable to override the WTP profile power level configuration.
                        choices:
                            - 'disable'
                            - 'enable'
                    override_vaps:
                        aliases: ['override-vaps']
                        type: str
                        description: Enable to override WTP profile Virtual Access Point
                        choices:
                            - 'disable'
                            - 'enable'
                    power_level:
                        aliases: ['power-level']
                        type: int
                        description: Radio EIRP power level as a percentage of the maximum EIRP power
                    power_mode:
                        aliases: ['power-mode']
                        type: str
                        description: Set radio effective isotropic radiated power
                        choices:
                            - 'dBm'
                            - 'percentage'
                    power_value:
                        aliases: ['power-value']
                        type: int
                        description: Radio EIRP power in dBm
                    radio_id:
                        aliases: ['radio-id']
                        type: int
                        description: Radio id.
                    vap_all:
                        aliases: ['vap-all']
                        type: str
                        description: Configure method for assigning SSIDs to this FortiAP
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'tunnel'
                            - 'bridge'
                            - 'manual'
                    vap1:
                        type: str
                        description: Virtual Access Point
                    vap2:
                        type: str
                        description: Virtual Access Point
                    vap3:
                        type: str
                        description: Virtual Access Point
                    vap4:
                        type: str
                        description: Virtual Access Point
                    vap5:
                        type: str
                        description: Virtual Access Point
                    vap6:
                        type: str
                        description: Virtual Access Point
                    vap7:
                        type: str
                        description: Virtual Access Point
                    vap8:
                        type: str
                        description: Virtual Access Point
                    vaps:
                        type: list
                        elements: str
                        description: Manually selected list of Virtual Access Points
                    spectrum_analysis:
                        aliases: ['spectrum-analysis']
                        type: str
                        description: Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'scan-only'
                    override_analysis:
                        aliases: ['override-analysis']
                        type: str
                        description: Enable to override the WTP profile spectrum analysis configuration.
                        choices:
                            - 'disable'
                            - 'enable'
            region:
                type: list
                elements: str
                description: Region name WTP is associated with.
            region_x:
                aliases: ['region-x']
                type: str
                description: Relative horizontal region coordinate
            region_y:
                aliases: ['region-y']
                type: str
                description: Relative vertical region coordinate
            split_tunneling_acl:
                aliases: ['split-tunneling-acl']
                type: list
                elements: dict
                description: Split tunneling acl.
                suboptions:
                    dest_ip:
                        aliases: ['dest-ip']
                        type: list
                        elements: str
                        description: Destination IP and mask for the split-tunneling subnet.
                    id:
                        type: int
                        description: ID.
            split_tunneling_acl_local_ap_subnet:
                aliases: ['split-tunneling-acl-local-ap-subnet']
                type: str
                description: Enable/disable automatically adding local subnetwork of FortiAP to split-tunneling ACL
                choices:
                    - 'disable'
                    - 'enable'
            split_tunneling_acl_path:
                aliases: ['split-tunneling-acl-path']
                type: str
                description: Split tunneling ACL path is local/tunnel.
                choices:
                    - 'tunnel'
                    - 'local'
            tun_mtu_downlink:
                aliases: ['tun-mtu-downlink']
                type: int
                description: The MTU of downlink CAPWAP tunnel
            tun_mtu_uplink:
                aliases: ['tun-mtu-uplink']
                type: int
                description: The maximum transmission unit
            uuid:
                type: str
                description: Universally Unique Identifier
            wan_port_mode:
                aliases: ['wan-port-mode']
                type: str
                description: Enable/disable using the FortiAP WAN port as a LAN port.
                choices:
                    - 'wan-lan'
                    - 'wan-only'
            wtp_id:
                aliases: ['wtp-id']
                type: str
                description: WTP ID.
            wtp_mode:
                aliases: ['wtp-mode']
                type: str
                description: WTP, AP, or FortiAP operating mode
                choices:
                    - 'normal'
                    - 'remote'
            wtp_profile:
                aliases: ['wtp-profile']
                type: list
                elements: str
                description: WTP profile name to apply to this WTP, AP or FortiAP.
            comment:
                type: str
                description: Comment.
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
    - name: Configure Wireless Termination Points
      fortinet.fmgdevice.fmgd_wireless_wtp:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        wireless_wtp:
          wtp_id: "your value" # Required variable, string
          # admin: <value in [discovery, disable, enable, ...]>
          # allowaccess:
          #   - "https"
          #   - "ssh"
          #   - "snmp"
          #   - "http"
          #   - "telnet"
          # apcfg_profile: <list or string>
          # ble_major_id: <integer>
          # ble_minor_id: <integer>
          # bonjour_profile: <list or string>
          # coordinate_latitude: <string>
          # coordinate_longitude: <string>
          # firmware_provision: <string>
          # firmware_provision_latest: <value in [disable, once]>
          # image_download: <value in [disable, enable]>
          # index: <integer>
          # ip_fragment_preventing:
          #   - "tcp-mss-adjust"
          #   - "icmp-unreachable"
          # lan:
          #   port_esl_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port_esl_ssid: <list or string>
          #   port_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port_ssid: <list or string>
          #   port1_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port1_ssid: <list or string>
          #   port2_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port2_ssid: <list or string>
          #   port3_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port3_ssid: <list or string>
          #   port4_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port4_ssid: <list or string>
          #   port5_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port5_ssid: <list or string>
          #   port6_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port6_ssid: <list or string>
          #   port7_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port7_ssid: <list or string>
          #   port8_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port8_ssid: <list or string>
          # led_state: <value in [disable, enable]>
          # location: <string>
          # login_passwd: <list or string>
          # login_passwd_change: <value in [no, yes, default]>
          # mesh_bridge_enable: <value in [disable, enable, default]>
          # name: <string>
          # override_allowaccess: <value in [disable, enable]>
          # override_ip_fragment: <value in [disable, enable]>
          # override_lan: <value in [disable, enable]>
          # override_led_state: <value in [disable, enable]>
          # override_login_passwd_change: <value in [disable, enable]>
          # override_split_tunnel: <value in [disable, enable]>
          # override_wan_port_mode: <value in [disable, enable]>
          # purdue_level: <value in [1, 2, 3, ...]>
          # radio_1:
          #   auto_power_high: <integer>
          #   auto_power_level: <value in [disable, enable]>
          #   auto_power_low: <integer>
          #   auto_power_target: <string>
          #   band:
          #     - "802.11a"
          #     - "802.11b"
          #     - "802.11g"
          #     - "802.11n"
          #     - "802.11n-5G"
          #     - "802.11n,g-only"
          #     - "802.11g-only"
          #     - "802.11n-only"
          #     - "802.11n-5G-only"
          #     - "802.11ac"
          #     - "802.11ac,n-only"
          #     - "802.11ac-only"
          #     - "802.11ax-5G"
          #     - "802.11ax,ac-only"
          #     - "802.11ax,ac,n-only"
          #     - "802.11ax-5G-only"
          #     - "802.11ax"
          #     - "802.11ax,n-only"
          #     - "802.11ax,n,g-only"
          #     - "802.11ax-only"
          #     - "802.11ac-2G"
          #     - "802.11ax-6G"
          #     - "802.11n-2G"
          #     - "802.11ac-5G"
          #     - "802.11ax-2G"
          #     - "802.11be-2G"
          #     - "802.11be-5G"
          #     - "802.11be-6G"
          #   channel: <list or string>
          #   drma_manual_mode: <value in [ap, monitor, ncf, ...]>
          #   override_band: <value in [disable, enable]>
          #   override_channel: <value in [disable, enable]>
          #   override_txpower: <value in [disable, enable]>
          #   override_vaps: <value in [disable, enable]>
          #   power_level: <integer>
          #   power_mode: <value in [dBm, percentage]>
          #   power_value: <integer>
          #   radio_id: <integer>
          #   vap_all: <value in [disable, enable, tunnel, ...]>
          #   vap1: <string>
          #   vap2: <string>
          #   vap3: <string>
          #   vap4: <string>
          #   vap5: <string>
          #   vap6: <string>
          #   vap7: <string>
          #   vap8: <string>
          #   vaps: <list or string>
          #   spectrum_analysis: <value in [disable, enable, scan-only]>
          #   override_analysis: <value in [disable, enable]>
          # radio_2:
          #   auto_power_high: <integer>
          #   auto_power_level: <value in [disable, enable]>
          #   auto_power_low: <integer>
          #   auto_power_target: <string>
          #   band:
          #     - "802.11a"
          #     - "802.11b"
          #     - "802.11g"
          #     - "802.11n"
          #     - "802.11n-5G"
          #     - "802.11n,g-only"
          #     - "802.11g-only"
          #     - "802.11n-only"
          #     - "802.11n-5G-only"
          #     - "802.11ac"
          #     - "802.11ac,n-only"
          #     - "802.11ac-only"
          #     - "802.11ax-5G"
          #     - "802.11ax,ac-only"
          #     - "802.11ax,ac,n-only"
          #     - "802.11ax-5G-only"
          #     - "802.11ax"
          #     - "802.11ax,n-only"
          #     - "802.11ax,n,g-only"
          #     - "802.11ax-only"
          #     - "802.11ac-2G"
          #     - "802.11ax-6G"
          #     - "802.11n-2G"
          #     - "802.11ac-5G"
          #     - "802.11ax-2G"
          #     - "802.11be-2G"
          #     - "802.11be-5G"
          #     - "802.11be-6G"
          #   channel: <list or string>
          #   drma_manual_mode: <value in [ap, monitor, ncf, ...]>
          #   override_band: <value in [disable, enable]>
          #   override_channel: <value in [disable, enable]>
          #   override_txpower: <value in [disable, enable]>
          #   override_vaps: <value in [disable, enable]>
          #   power_level: <integer>
          #   power_mode: <value in [dBm, percentage]>
          #   power_value: <integer>
          #   radio_id: <integer>
          #   vap_all: <value in [disable, enable, tunnel, ...]>
          #   vap1: <string>
          #   vap2: <string>
          #   vap3: <string>
          #   vap4: <string>
          #   vap5: <string>
          #   vap6: <string>
          #   vap7: <string>
          #   vap8: <string>
          #   vaps: <list or string>
          #   spectrum_analysis: <value in [disable, enable, scan-only]>
          #   override_analysis: <value in [disable, enable]>
          # radio_3:
          #   auto_power_high: <integer>
          #   auto_power_level: <value in [disable, enable]>
          #   auto_power_low: <integer>
          #   auto_power_target: <string>
          #   band:
          #     - "802.11a"
          #     - "802.11b"
          #     - "802.11g"
          #     - "802.11n"
          #     - "802.11n-5G"
          #     - "802.11n,g-only"
          #     - "802.11g-only"
          #     - "802.11n-only"
          #     - "802.11n-5G-only"
          #     - "802.11ac"
          #     - "802.11ac,n-only"
          #     - "802.11ac-only"
          #     - "802.11ax-5G"
          #     - "802.11ax,ac-only"
          #     - "802.11ax,ac,n-only"
          #     - "802.11ax-5G-only"
          #     - "802.11ax"
          #     - "802.11ax,n-only"
          #     - "802.11ax,n,g-only"
          #     - "802.11ax-only"
          #     - "802.11ac-2G"
          #     - "802.11ax-6G"
          #     - "802.11n-2G"
          #     - "802.11ac-5G"
          #     - "802.11ax-2G"
          #     - "802.11be-2G"
          #     - "802.11be-5G"
          #     - "802.11be-6G"
          #   channel: <list or string>
          #   drma_manual_mode: <value in [ap, monitor, ncf, ...]>
          #   override_band: <value in [disable, enable]>
          #   override_channel: <value in [disable, enable]>
          #   override_txpower: <value in [disable, enable]>
          #   override_vaps: <value in [disable, enable]>
          #   power_level: <integer>
          #   power_mode: <value in [dBm, percentage]>
          #   power_value: <integer>
          #   radio_id: <integer>
          #   vap_all: <value in [disable, enable, tunnel, ...]>
          #   vap1: <string>
          #   vap2: <string>
          #   vap3: <string>
          #   vap4: <string>
          #   vap5: <string>
          #   vap6: <string>
          #   vap7: <string>
          #   vap8: <string>
          #   vaps: <list or string>
          #   spectrum_analysis: <value in [disable, enable, scan-only]>
          #   override_analysis: <value in [disable, enable]>
          # radio_4:
          #   auto_power_high: <integer>
          #   auto_power_level: <value in [disable, enable]>
          #   auto_power_low: <integer>
          #   auto_power_target: <string>
          #   band:
          #     - "802.11a"
          #     - "802.11b"
          #     - "802.11g"
          #     - "802.11n"
          #     - "802.11n-5G"
          #     - "802.11n,g-only"
          #     - "802.11g-only"
          #     - "802.11n-only"
          #     - "802.11n-5G-only"
          #     - "802.11ac"
          #     - "802.11ac,n-only"
          #     - "802.11ac-only"
          #     - "802.11ax-5G"
          #     - "802.11ax,ac-only"
          #     - "802.11ax,ac,n-only"
          #     - "802.11ax-5G-only"
          #     - "802.11ax"
          #     - "802.11ax,n-only"
          #     - "802.11ax,n,g-only"
          #     - "802.11ax-only"
          #     - "802.11ac-2G"
          #     - "802.11ax-6G"
          #     - "802.11n-2G"
          #     - "802.11ac-5G"
          #     - "802.11ax-2G"
          #     - "802.11be-2G"
          #     - "802.11be-5G"
          #     - "802.11be-6G"
          #   channel: <list or string>
          #   drma_manual_mode: <value in [ap, monitor, ncf, ...]>
          #   override_band: <value in [disable, enable]>
          #   override_channel: <value in [disable, enable]>
          #   override_txpower: <value in [disable, enable]>
          #   override_vaps: <value in [disable, enable]>
          #   power_level: <integer>
          #   power_mode: <value in [dBm, percentage]>
          #   power_value: <integer>
          #   radio_id: <integer>
          #   vap_all: <value in [disable, enable, tunnel, ...]>
          #   vap1: <string>
          #   vap2: <string>
          #   vap3: <string>
          #   vap4: <string>
          #   vap5: <string>
          #   vap6: <string>
          #   vap7: <string>
          #   vap8: <string>
          #   vaps: <list or string>
          #   spectrum_analysis: <value in [disable, enable, scan-only]>
          #   override_analysis: <value in [disable, enable]>
          # region: <list or string>
          # region_x: <string>
          # region_y: <string>
          # split_tunneling_acl:
          #   - dest_ip: <list or string>
          #     id: <integer>
          # split_tunneling_acl_local_ap_subnet: <value in [disable, enable]>
          # split_tunneling_acl_path: <value in [tunnel, local]>
          # tun_mtu_downlink: <integer>
          # tun_mtu_uplink: <integer>
          # uuid: <string>
          # wan_port_mode: <value in [wan-lan, wan-only]>
          # wtp_mode: <value in [normal, remote]>
          # wtp_profile: <list or string>
          # comment: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'wtp_id'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wireless_wtp': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'admin': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['discovery', 'disable', 'enable', 'discovered'], 'type': 'str'},
                'allowaccess': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['https', 'ssh', 'snmp', 'http', 'telnet'],
                    'elements': 'str'
                },
                'apcfg-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ble-major-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ble-minor-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'bonjour-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'coordinate-latitude': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'coordinate-longitude': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'firmware-provision': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'firmware-provision-latest': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'once'], 'type': 'str'},
                'image-download': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'index': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ip-fragment-preventing': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['tcp-mss-adjust', 'icmp-unreachable'],
                    'elements': 'str'
                },
                'lan': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'port-esl-mode': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port-esl-ssid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'port-mode': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port-ssid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'port1-mode': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port1-ssid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'port2-mode': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port2-ssid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'port3-mode': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port3-ssid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'port4-mode': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port4-ssid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'port5-mode': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port5-ssid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'port6-mode': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port6-ssid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'port7-mode': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port7-ssid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'port8-mode': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port8-ssid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    }
                },
                'led-state': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'location': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'login-passwd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'login-passwd-change': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['no', 'yes', 'default'], 'type': 'str'},
                'mesh-bridge-enable': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'default'], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'override-allowaccess': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-ip-fragment': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-lan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-led-state': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-login-passwd-change': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-split-tunnel': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-wan-port-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'purdue-level': {'v_range': [['7.4.3', '']], 'choices': ['1', '2', '3', '4', '5', '1.5', '2.5', '3.5', '5.5'], 'type': 'str'},
                'radio-1': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'auto-power-high': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'auto-power-level': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'auto-power-low': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'auto-power-target': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'band': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': [
                                '802.11a', '802.11b', '802.11g', '802.11n', '802.11n-5G', '802.11n,g-only', '802.11g-only', '802.11n-only',
                                '802.11n-5G-only', '802.11ac', '802.11ac,n-only', '802.11ac-only', '802.11ax-5G', '802.11ax,ac-only',
                                '802.11ax,ac,n-only', '802.11ax-5G-only', '802.11ax', '802.11ax,n-only', '802.11ax,n,g-only', '802.11ax-only',
                                '802.11ac-2G', '802.11ax-6G', '802.11n-2G', '802.11ac-5G', '802.11ax-2G', '802.11be-2G', '802.11be-5G', '802.11be-6G'
                            ],
                            'elements': 'str'
                        },
                        'channel': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'drma-manual-mode': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['ap', 'monitor', 'ncf', 'ncf-peek'],
                            'type': 'str'
                        },
                        'override-band': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'override-channel': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'override-txpower': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'override-vaps': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'power-level': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'power-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['dBm', 'percentage'], 'type': 'str'},
                        'power-value': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'radio-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'vap-all': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['disable', 'enable', 'tunnel', 'bridge', 'manual'],
                            'type': 'str'
                        },
                        'vap1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap5': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap7': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap8': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vaps': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'spectrum-analysis': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['disable', 'enable', 'scan-only'],
                            'type': 'str'
                        },
                        'override-analysis': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'radio-2': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'auto-power-high': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'auto-power-level': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'auto-power-low': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'auto-power-target': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'band': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': [
                                '802.11a', '802.11b', '802.11g', '802.11n', '802.11n-5G', '802.11n,g-only', '802.11g-only', '802.11n-only',
                                '802.11n-5G-only', '802.11ac', '802.11ac,n-only', '802.11ac-only', '802.11ax-5G', '802.11ax,ac-only',
                                '802.11ax,ac,n-only', '802.11ax-5G-only', '802.11ax', '802.11ax,n-only', '802.11ax,n,g-only', '802.11ax-only',
                                '802.11ac-2G', '802.11ax-6G', '802.11n-2G', '802.11ac-5G', '802.11ax-2G', '802.11be-2G', '802.11be-5G', '802.11be-6G'
                            ],
                            'elements': 'str'
                        },
                        'channel': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'drma-manual-mode': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['ap', 'monitor', 'ncf', 'ncf-peek'],
                            'type': 'str'
                        },
                        'override-band': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'override-channel': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'override-txpower': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'override-vaps': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'power-level': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'power-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['dBm', 'percentage'], 'type': 'str'},
                        'power-value': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'radio-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'vap-all': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['disable', 'enable', 'tunnel', 'bridge', 'manual'],
                            'type': 'str'
                        },
                        'vap1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap5': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap7': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap8': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vaps': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'spectrum-analysis': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['disable', 'enable', 'scan-only'],
                            'type': 'str'
                        },
                        'override-analysis': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'radio-3': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'auto-power-high': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'auto-power-level': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'auto-power-low': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'auto-power-target': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'band': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': [
                                '802.11a', '802.11b', '802.11g', '802.11n', '802.11n-5G', '802.11n,g-only', '802.11g-only', '802.11n-only',
                                '802.11n-5G-only', '802.11ac', '802.11ac,n-only', '802.11ac-only', '802.11ax-5G', '802.11ax,ac-only',
                                '802.11ax,ac,n-only', '802.11ax-5G-only', '802.11ax', '802.11ax,n-only', '802.11ax,n,g-only', '802.11ax-only',
                                '802.11ac-2G', '802.11ax-6G', '802.11n-2G', '802.11ac-5G', '802.11ax-2G', '802.11be-2G', '802.11be-5G', '802.11be-6G'
                            ],
                            'elements': 'str'
                        },
                        'channel': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'drma-manual-mode': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['ap', 'monitor', 'ncf', 'ncf-peek'],
                            'type': 'str'
                        },
                        'override-band': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'override-channel': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'override-txpower': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'override-vaps': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'power-level': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'power-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['dBm', 'percentage'], 'type': 'str'},
                        'power-value': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'radio-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'vap-all': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['disable', 'enable', 'tunnel', 'bridge', 'manual'],
                            'type': 'str'
                        },
                        'vap1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap5': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap7': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap8': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vaps': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'spectrum-analysis': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['disable', 'enable', 'scan-only'],
                            'type': 'str'
                        },
                        'override-analysis': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'radio-4': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'auto-power-high': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'auto-power-level': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'auto-power-low': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'auto-power-target': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'band': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': [
                                '802.11a', '802.11b', '802.11g', '802.11n', '802.11n-5G', '802.11n,g-only', '802.11g-only', '802.11n-only',
                                '802.11n-5G-only', '802.11ac', '802.11ac,n-only', '802.11ac-only', '802.11ax-5G', '802.11ax,ac-only',
                                '802.11ax,ac,n-only', '802.11ax-5G-only', '802.11ax', '802.11ax,n-only', '802.11ax,n,g-only', '802.11ax-only',
                                '802.11ac-2G', '802.11ax-6G', '802.11n-2G', '802.11ac-5G', '802.11ax-2G', '802.11be-2G', '802.11be-5G', '802.11be-6G'
                            ],
                            'elements': 'str'
                        },
                        'channel': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'drma-manual-mode': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['ap', 'monitor', 'ncf', 'ncf-peek'],
                            'type': 'str'
                        },
                        'override-band': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'override-channel': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'override-txpower': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'override-vaps': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'power-level': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'power-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['dBm', 'percentage'], 'type': 'str'},
                        'power-value': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'radio-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'vap-all': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['disable', 'enable', 'tunnel', 'bridge', 'manual'],
                            'type': 'str'
                        },
                        'vap1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap5': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap7': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vap8': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vaps': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'spectrum-analysis': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['disable', 'enable', 'scan-only'],
                            'type': 'str'
                        },
                        'override-analysis': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'region': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'region-x': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'region-y': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'split-tunneling-acl': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'dest-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'split-tunneling-acl-local-ap-subnet': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'split-tunneling-acl-path': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['tunnel', 'local'], 'type': 'str'},
                'tun-mtu-downlink': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'tun-mtu-uplink': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'uuid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'wan-port-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['wan-lan', 'wan-only'], 'type': 'str'},
                'wtp-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'wtp-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['normal', 'remote'], 'type': 'str'},
                'wtp-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'comment': {'v_range': [['7.6.2', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_wtp'),
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
