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
module: fmgd_switchcontroller_managedswitch_ports
short_description: Managed-switch port list.
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
    managed-switch:
        description: Deprecated, please use "managed_switch"
        type: str
    managed_switch:
        description: The parameter (managed-switch) in requested url.
        type: str
    switchcontroller_managedswitch_ports:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            access_mode:
                aliases: ['access-mode']
                type: str
                description: Access mode of the port.
                choices:
                    - 'normal'
                    - 'nac'
                    - 'dynamic'
                    - 'static'
            acl_group:
                aliases: ['acl-group']
                type: list
                elements: str
                description: ACL groups on this port.
            aggregator_mode:
                aliases: ['aggregator-mode']
                type: str
                description: LACP member select mode.
                choices:
                    - 'bandwidth'
                    - 'count'
            allow_arp_monitor:
                aliases: ['allow-arp-monitor']
                type: str
                description: Enable/Disable allow ARP monitor.
                choices:
                    - 'disable'
                    - 'enable'
            allowed_vlans:
                aliases: ['allowed-vlans']
                type: list
                elements: str
                description: Configure switch port tagged VLANs.
            allowed_vlans_all:
                aliases: ['allowed-vlans-all']
                type: str
                description: Enable/disable all defined vlans on this port.
                choices:
                    - 'disable'
                    - 'enable'
            arp_inspection_trust:
                aliases: ['arp-inspection-trust']
                type: str
                description: Trusted or untrusted dynamic ARP inspection.
                choices:
                    - 'untrusted'
                    - 'trusted'
            authenticated_port:
                aliases: ['authenticated-port']
                type: int
                description: Authenticated port.
            bundle:
                type: str
                description: Enable/disable Link Aggregation Group
                choices:
                    - 'disable'
                    - 'enable'
            description:
                type: str
                description: Description for port.
            dhcp_snoop_option82_override:
                aliases: ['dhcp-snoop-option82-override']
                type: list
                elements: dict
                description: Dhcp snoop option82 override.
                suboptions:
                    circuit_id:
                        aliases: ['circuit-id']
                        type: str
                        description: Circuit ID string.
                    remote_id:
                        aliases: ['remote-id']
                        type: str
                        description: Remote ID string.
                    vlan_name:
                        aliases: ['vlan-name']
                        type: list
                        elements: str
                        description: DHCP snooping option 82 VLAN.
            dhcp_snoop_option82_trust:
                aliases: ['dhcp-snoop-option82-trust']
                type: str
                description: Enable/disable allowance of DHCP with option-82 on untrusted interface.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_snooping:
                aliases: ['dhcp-snooping']
                type: str
                description: Trusted or untrusted DHCP-snooping interface.
                choices:
                    - 'trusted'
                    - 'untrusted'
            discard_mode:
                aliases: ['discard-mode']
                type: str
                description: Configure discard mode for port.
                choices:
                    - 'none'
                    - 'all-untagged'
                    - 'all-tagged'
            dsl_profile:
                aliases: ['dsl-profile']
                type: list
                elements: str
                description: DSL policy configuration.
            edge_port:
                aliases: ['edge-port']
                type: str
                description: Enable/disable this interface as an edge port, bridging connections between workstations and/or computers.
                choices:
                    - 'disable'
                    - 'enable'
            encrypted_port:
                aliases: ['encrypted-port']
                type: int
                description: Encrypted port.
            export_to:
                aliases: ['export-to']
                type: list
                elements: str
                description: Export managed-switch port to a tenant VDOM.
            export_to_pool:
                aliases: ['export-to-pool']
                type: list
                elements: str
                description: Switch controller export port to pool-list.
            export_to_pool_flag:
                aliases: ['export-to-pool-flag']
                type: int
                description: Switch controller export port to pool-list.
            fallback_port:
                aliases: ['fallback-port']
                type: str
                description: LACP fallback port.
            fec_capable:
                aliases: ['fec-capable']
                type: int
                description: FEC capable.
            fec_state:
                aliases: ['fec-state']
                type: str
                description: State of forward error correction.
                choices:
                    - 'disabled'
                    - 'cl74'
                    - 'cl91'
                    - 'detect-by-module'
            fgt_peer_device_name:
                aliases: ['fgt-peer-device-name']
                type: str
                description: Fgt peer device name.
            fgt_peer_port_name:
                aliases: ['fgt-peer-port-name']
                type: str
                description: Fgt peer port name.
            fiber_port:
                aliases: ['fiber-port']
                type: int
                description: Fiber port.
            flags:
                type: int
                description: Flags.
            flap_duration:
                aliases: ['flap-duration']
                type: int
                description: Period over which flap events are calculated
            flap_rate:
                aliases: ['flap-rate']
                type: int
                description: Number of stage change events needed within flap-duration.
            flap_timeout:
                aliases: ['flap-timeout']
                type: int
                description: Flap guard disabling protection
            flapguard:
                type: str
                description: Enable/disable flap guard.
                choices:
                    - 'disable'
                    - 'enable'
            flow_control:
                aliases: ['flow-control']
                type: str
                description: Flow control direction.
                choices:
                    - 'disable'
                    - 'tx'
                    - 'rx'
                    - 'both'
            fortilink_port:
                aliases: ['fortilink-port']
                type: int
                description: Fortilink port.
            fortiswitch_acls:
                aliases: ['fortiswitch-acls']
                type: list
                elements: int
                description: ACLs on this port.
            igmp_snooping_flood_reports:
                aliases: ['igmp-snooping-flood-reports']
                type: str
                description: Enable/disable flooding of IGMP reports to this interface when igmp-snooping enabled.
                choices:
                    - 'disable'
                    - 'enable'
            interface_tags:
                aliases: ['interface-tags']
                type: list
                elements: str
                description: Tag
            ip_source_guard:
                aliases: ['ip-source-guard']
                type: str
                description: Enable/disable IP source guard.
                choices:
                    - 'disable'
                    - 'enable'
            isl_local_trunk_name:
                aliases: ['isl-local-trunk-name']
                type: str
                description: Isl local trunk name.
            isl_peer_device_name:
                aliases: ['isl-peer-device-name']
                type: str
                description: Isl peer device name.
            isl_peer_device_sn:
                aliases: ['isl-peer-device-sn']
                type: str
                description: Isl peer device sn.
            isl_peer_port_name:
                aliases: ['isl-peer-port-name']
                type: str
                description: Isl peer port name.
            lacp_speed:
                aliases: ['lacp-speed']
                type: str
                description: End Link Aggregation Control Protocol
                choices:
                    - 'slow'
                    - 'fast'
            learning_limit:
                aliases: ['learning-limit']
                type: int
                description: Limit the number of dynamic MAC addresses on this Port
            link_status:
                aliases: ['link-status']
                type: str
                description: Link status.
                choices:
                    - 'down'
                    - 'up'
            lldp_profile:
                aliases: ['lldp-profile']
                type: list
                elements: str
                description: LLDP port TLV profile.
            lldp_status:
                aliases: ['lldp-status']
                type: str
                description: LLDP transmit and receive status.
                choices:
                    - 'disable'
                    - 'rx-only'
                    - 'tx-only'
                    - 'tx-rx'
            loop_guard:
                aliases: ['loop-guard']
                type: str
                description: Enable/disable loop-guard on this interface, an STP optimization used to prevent network loops.
                choices:
                    - 'disabled'
                    - 'enabled'
            loop_guard_timeout:
                aliases: ['loop-guard-timeout']
                type: int
                description: Loop-guard timeout
            mac_addr:
                aliases: ['mac-addr']
                type: str
                description: Port/Trunk MAC.
            matched_dpp_intf_tags:
                aliases: ['matched-dpp-intf-tags']
                type: str
                description: Matched interface tags in the dynamic port policy.
            matched_dpp_policy:
                aliases: ['matched-dpp-policy']
                type: str
                description: Matched child policy in the dynamic port policy.
            max_bundle:
                aliases: ['max-bundle']
                type: int
                description: Maximum size of LAG bundle
            mcast_snooping_flood_traffic:
                aliases: ['mcast-snooping-flood-traffic']
                type: str
                description: Enable/disable flooding of IGMP snooping traffic to this interface.
                choices:
                    - 'disable'
                    - 'enable'
            mclag:
                type: str
                description: Enable/disable multi-chassis link aggregation
                choices:
                    - 'disable'
                    - 'enable'
            mclag_icl_port:
                aliases: ['mclag-icl-port']
                type: int
                description: Mclag icl port.
            media_type:
                aliases: ['media-type']
                type: str
                description: Media type.
            member_withdrawal_behavior:
                aliases: ['member-withdrawal-behavior']
                type: str
                description: Port behavior after it withdraws because of loss of control packets.
                choices:
                    - 'forward'
                    - 'block'
            members:
                type: list
                elements: str
                description: Aggregated LAG bundle interfaces.
            min_bundle:
                aliases: ['min-bundle']
                type: int
                description: Minimum size of LAG bundle
            mode:
                type: str
                description: LACP mode
                choices:
                    - 'static'
                    - 'lacp-passive'
                    - 'lacp-active'
            p2p_port:
                aliases: ['p2p-port']
                type: int
                description: P2p port.
            packet_sample_rate:
                aliases: ['packet-sample-rate']
                type: int
                description: Packet sampling rate
            packet_sampler:
                aliases: ['packet-sampler']
                type: str
                description: Enable/disable packet sampling on this interface.
                choices:
                    - 'disabled'
                    - 'enabled'
            pause_meter:
                aliases: ['pause-meter']
                type: int
                description: Configure ingress pause metering rate, in kbps
            pause_meter_resume:
                aliases: ['pause-meter-resume']
                type: str
                description: Resume threshold for resuming traffic on ingress port.
                choices:
                    - '25%'
                    - '50%'
                    - '75%'
            poe_capable:
                aliases: ['poe-capable']
                type: int
                description: PoE capable.
            poe_max_power:
                aliases: ['poe-max-power']
                type: str
                description: Poe max power.
            poe_mode_bt_cabable:
                aliases: ['poe-mode-bt-cabable']
                type: int
                description: PoE mode IEEE 802.
            poe_port_mode:
                aliases: ['poe-port-mode']
                type: str
                description: Configure PoE port mode.
                choices:
                    - 'ieee802-3af'
                    - 'ieee802-3at'
                    - 'ieee802-3bt'
            poe_port_power:
                aliases: ['poe-port-power']
                type: str
                description: Configure PoE port power.
                choices:
                    - 'normal'
                    - 'perpetual'
                    - 'perpetual-fast'
            poe_port_priority:
                aliases: ['poe-port-priority']
                type: str
                description: Configure PoE port priority.
                choices:
                    - 'critical-priority'
                    - 'high-priority'
                    - 'low-priority'
                    - 'medium-priority'
            poe_pre_standard_detection:
                aliases: ['poe-pre-standard-detection']
                type: str
                description: Enable/disable PoE pre-standard detection.
                choices:
                    - 'disable'
                    - 'enable'
            poe_standard:
                aliases: ['poe-standard']
                type: str
                description: Poe standard.
            poe_status:
                aliases: ['poe-status']
                type: str
                description: Enable/disable PoE status.
                choices:
                    - 'disable'
                    - 'enable'
            port_name:
                aliases: ['port-name']
                type: str
                description: Switch port name.
            port_number:
                aliases: ['port-number']
                type: int
                description: Port number.
            port_owner:
                aliases: ['port-owner']
                type: str
                description: Switch port name.
            port_policy:
                aliases: ['port-policy']
                type: list
                elements: str
                description: Switch controller dynamic port policy from available options.
            port_prefix_type:
                aliases: ['port-prefix-type']
                type: int
                description: Port prefix type.
            port_security_policy:
                aliases: ['port-security-policy']
                type: list
                elements: str
                description: Switch controller authentication policy to apply to this managed switch from available options.
            port_selection_criteria:
                aliases: ['port-selection-criteria']
                type: str
                description: Algorithm for aggregate port selection.
                choices:
                    - 'src-mac'
                    - 'dst-mac'
                    - 'src-dst-mac'
                    - 'src-ip'
                    - 'dst-ip'
                    - 'src-dst-ip'
            ptp_policy:
                aliases: ['ptp-policy']
                type: list
                elements: str
                description: PTP policy configuration.
            ptp_status:
                aliases: ['ptp-status']
                type: str
                description: Enable/disable PTP policy on this FortiSwitch port.
                choices:
                    - 'disable'
                    - 'enable'
            qos_policy:
                aliases: ['qos-policy']
                type: list
                elements: str
                description: Switch controller QoS policy from available options.
            restricted_auth_port:
                aliases: ['restricted-auth-port']
                type: int
                description: Restricted auth port.
            rpvst_port:
                aliases: ['rpvst-port']
                type: str
                description: Enable/disable inter-operability with rapid PVST on this interface.
                choices:
                    - 'disabled'
                    - 'enabled'
            sample_direction:
                aliases: ['sample-direction']
                type: str
                description: Packet sampling direction.
                choices:
                    - 'rx'
                    - 'tx'
                    - 'both'
            sflow_counter_interval:
                aliases: ['sflow-counter-interval']
                type: int
                description: SFlow sampling counter polling interval in seconds
            speed:
                type: str
                description: Switch port speed; default and available settings depend on hardware.
                choices:
                    - 'auto'
                    - '10full'
                    - '10half'
                    - '100full'
                    - '100half'
                    - '1000full'
                    - '10000full'
                    - '1000auto'
                    - '40000full'
                    - '1000fiber'
                    - '10000'
                    - '40000'
                    - 'auto-module'
                    - '100FX-half'
                    - '100FX-full'
                    - '100000full'
                    - '2500full'
                    - '25000full'
                    - '50000full'
                    - '40000auto'
                    - '10000cr'
                    - '10000sr'
                    - '100000sr4'
                    - '100000cr4'
                    - '25000cr4'
                    - '25000sr4'
                    - '5000full'
                    - '2500auto'
                    - '5000auto'
                    - '1000full-fiber'
                    - '40000sr4'
                    - '40000cr4'
                    - '25000cr'
                    - '25000sr'
                    - '50000cr'
                    - '50000sr'
            speed_mask:
                aliases: ['speed-mask']
                type: int
                description: Switch port speed mask.
            stacking_port:
                aliases: ['stacking-port']
                type: int
                description: Stacking port.
            status:
                type: str
                description: Switch port admin status
                choices:
                    - 'down'
                    - 'up'
            sticky_mac:
                aliases: ['sticky-mac']
                type: str
                description: Enable or disable sticky-mac on the interface.
                choices:
                    - 'disable'
                    - 'enable'
            storm_control_policy:
                aliases: ['storm-control-policy']
                type: list
                elements: str
                description: Switch controller storm control policy from available options.
            stp_bpdu_guard:
                aliases: ['stp-bpdu-guard']
                type: str
                description: Enable/disable STP BPDU guard on this interface.
                choices:
                    - 'disabled'
                    - 'enabled'
            stp_bpdu_guard_timeout:
                aliases: ['stp-bpdu-guard-timeout']
                type: int
                description: BPDU Guard disabling protection
            stp_root_guard:
                aliases: ['stp-root-guard']
                type: str
                description: Enable/disable STP root guard on this interface.
                choices:
                    - 'disabled'
                    - 'enabled'
            stp_state:
                aliases: ['stp-state']
                type: str
                description: Enable/disable Spanning Tree Protocol
                choices:
                    - 'disabled'
                    - 'enabled'
            switch_id:
                aliases: ['switch-id']
                type: str
                description: Switch id.
            trunk_member:
                aliases: ['trunk-member']
                type: int
                description: Trunk member.
            type:
                type: str
                description: Interface type
                choices:
                    - 'physical'
                    - 'trunk'
            untagged_vlans:
                aliases: ['untagged-vlans']
                type: list
                elements: str
                description: Configure switch port untagged VLANs.
            virtual_port:
                aliases: ['virtual-port']
                type: int
                description: Virtualized switch port.
            vlan:
                type: list
                elements: str
                description: Assign switch ports to a VLAN.
            igmps_flood_reports:
                aliases: ['igmps-flood-reports']
                type: str
                description: Enable/disable flooding of IGMP reports to this interface when igmp-snooping enabled.
                choices:
                    - 'disable'
                    - 'enable'
            igmps_flood_traffic:
                aliases: ['igmps-flood-traffic']
                type: str
                description: Enable/disable flooding of IGMP snooping traffic to this interface.
                choices:
                    - 'disable'
                    - 'enable'
            export_tags:
                aliases: ['export-tags']
                type: list
                elements: str
                description: Configure export tag
            igmp_snooping:
                aliases: ['igmp-snooping']
                type: str
                description: Set IGMP snooping mode for the physical port interface.
                choices:
                    - 'disable'
                    - 'enable'
            log_mac_event:
                aliases: ['log-mac-event']
                type: str
                description: Enable/disable logging for dynamic MAC address events.
                choices:
                    - 'disable'
                    - 'enable'
            pd_capable:
                aliases: ['pd-capable']
                type: int
                description: Powered device capable.
            qnq:
                type: list
                elements: str
                description: '802.'
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
    - name: Managed-switch port list.
      fortinet.fmgdevice.fmgd_switchcontroller_managedswitch_ports:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        managed_switch: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_managedswitch_ports:
          # access_mode: <value in [normal, nac, dynamic, ...]>
          # acl_group: <list or string>
          # aggregator_mode: <value in [bandwidth, count]>
          # allow_arp_monitor: <value in [disable, enable]>
          # allowed_vlans: <list or string>
          # allowed_vlans_all: <value in [disable, enable]>
          # arp_inspection_trust: <value in [untrusted, trusted]>
          # authenticated_port: <integer>
          # bundle: <value in [disable, enable]>
          # description: <string>
          # dhcp_snoop_option82_override:
          #   - circuit_id: <string>
          #     remote_id: <string>
          #     vlan_name: <list or string>
          # dhcp_snoop_option82_trust: <value in [disable, enable]>
          # dhcp_snooping: <value in [trusted, untrusted]>
          # discard_mode: <value in [none, all-untagged, all-tagged]>
          # dsl_profile: <list or string>
          # edge_port: <value in [disable, enable]>
          # encrypted_port: <integer>
          # export_to: <list or string>
          # export_to_pool: <list or string>
          # export_to_pool_flag: <integer>
          # fallback_port: <string>
          # fec_capable: <integer>
          # fec_state: <value in [disabled, cl74, cl91, ...]>
          # fgt_peer_device_name: <string>
          # fgt_peer_port_name: <string>
          # fiber_port: <integer>
          # flags: <integer>
          # flap_duration: <integer>
          # flap_rate: <integer>
          # flap_timeout: <integer>
          # flapguard: <value in [disable, enable]>
          # flow_control: <value in [disable, tx, rx, ...]>
          # fortilink_port: <integer>
          # fortiswitch_acls: <list or integer>
          # igmp_snooping_flood_reports: <value in [disable, enable]>
          # interface_tags: <list or string>
          # ip_source_guard: <value in [disable, enable]>
          # isl_local_trunk_name: <string>
          # isl_peer_device_name: <string>
          # isl_peer_device_sn: <string>
          # isl_peer_port_name: <string>
          # lacp_speed: <value in [slow, fast]>
          # learning_limit: <integer>
          # link_status: <value in [down, up]>
          # lldp_profile: <list or string>
          # lldp_status: <value in [disable, rx-only, tx-only, ...]>
          # loop_guard: <value in [disabled, enabled]>
          # loop_guard_timeout: <integer>
          # mac_addr: <string>
          # matched_dpp_intf_tags: <string>
          # matched_dpp_policy: <string>
          # max_bundle: <integer>
          # mcast_snooping_flood_traffic: <value in [disable, enable]>
          # mclag: <value in [disable, enable]>
          # mclag_icl_port: <integer>
          # media_type: <string>
          # member_withdrawal_behavior: <value in [forward, block]>
          # members: <list or string>
          # min_bundle: <integer>
          # mode: <value in [static, lacp-passive, lacp-active]>
          # p2p_port: <integer>
          # packet_sample_rate: <integer>
          # packet_sampler: <value in [disabled, enabled]>
          # pause_meter: <integer>
          # pause_meter_resume: <value in [25%, 50%, 75%]>
          # poe_capable: <integer>
          # poe_max_power: <string>
          # poe_mode_bt_cabable: <integer>
          # poe_port_mode: <value in [ieee802-3af, ieee802-3at, ieee802-3bt]>
          # poe_port_power: <value in [normal, perpetual, perpetual-fast]>
          # poe_port_priority: <value in [critical-priority, high-priority, low-priority, ...]>
          # poe_pre_standard_detection: <value in [disable, enable]>
          # poe_standard: <string>
          # poe_status: <value in [disable, enable]>
          # port_name: <string>
          # port_number: <integer>
          # port_owner: <string>
          # port_policy: <list or string>
          # port_prefix_type: <integer>
          # port_security_policy: <list or string>
          # port_selection_criteria: <value in [src-mac, dst-mac, src-dst-mac, ...]>
          # ptp_policy: <list or string>
          # ptp_status: <value in [disable, enable]>
          # qos_policy: <list or string>
          # restricted_auth_port: <integer>
          # rpvst_port: <value in [disabled, enabled]>
          # sample_direction: <value in [rx, tx, both]>
          # sflow_counter_interval: <integer>
          # speed: <value in [auto, 10full, 10half, ...]>
          # speed_mask: <integer>
          # stacking_port: <integer>
          # status: <value in [down, up]>
          # sticky_mac: <value in [disable, enable]>
          # storm_control_policy: <list or string>
          # stp_bpdu_guard: <value in [disabled, enabled]>
          # stp_bpdu_guard_timeout: <integer>
          # stp_root_guard: <value in [disabled, enabled]>
          # stp_state: <value in [disabled, enabled]>
          # switch_id: <string>
          # trunk_member: <integer>
          # type: <value in [physical, trunk]>
          # untagged_vlans: <list or string>
          # virtual_port: <integer>
          # vlan: <list or string>
          # igmps_flood_reports: <value in [disable, enable]>
          # igmps_flood_traffic: <value in [disable, enable]>
          # export_tags: <list or string>
          # igmp_snooping: <value in [disable, enable]>
          # log_mac_event: <value in [disable, enable]>
          # pd_capable: <integer>
          # qnq: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/ports'
    ]
    url_params = ['device', 'vdom', 'managed-switch']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'managed-switch': {'type': 'str', 'api_name': 'managed_switch'},
        'managed_switch': {'type': 'str'},
        'switchcontroller_managedswitch_ports': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'access-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['normal', 'nac', 'dynamic', 'static'], 'type': 'str'},
                'acl-group': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'aggregator-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['bandwidth', 'count'], 'type': 'str'},
                'allow-arp-monitor': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'allowed-vlans': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'allowed-vlans-all': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'arp-inspection-trust': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['untrusted', 'trusted'], 'type': 'str'},
                'authenticated-port': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'bundle': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'description': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dhcp-snoop-option82-override': {
                    'v_range': [['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'circuit-id': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'remote-id': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'vlan-name': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'dhcp-snoop-option82-trust': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-snooping': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['trusted', 'untrusted'], 'type': 'str'},
                'discard-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'all-untagged', 'all-tagged'], 'type': 'str'},
                'dsl-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'edge-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'encrypted-port': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'export-to': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'export-to-pool': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'export-to-pool-flag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'fallback-port': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'fec-capable': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'fec-state': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disabled', 'cl74', 'cl91', 'detect-by-module'], 'type': 'str'},
                'fgt-peer-device-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'fgt-peer-port-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'fiber-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'flags': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'flap-duration': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'flap-rate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'flap-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'flapguard': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'flow-control': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'tx', 'rx', 'both'], 'type': 'str'},
                'fortilink-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'fortiswitch-acls': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'igmp-snooping-flood-reports': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'interface-tags': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ip-source-guard': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'isl-local-trunk-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'isl-peer-device-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'isl-peer-device-sn': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'isl-peer-port-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'lacp-speed': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['slow', 'fast'], 'type': 'str'},
                'learning-limit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'link-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['down', 'up'], 'type': 'str'},
                'lldp-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'lldp-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'rx-only', 'tx-only', 'tx-rx'], 'type': 'str'},
                'loop-guard': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disabled', 'enabled'], 'type': 'str'},
                'loop-guard-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'mac-addr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'matched-dpp-intf-tags': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'matched-dpp-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'max-bundle': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'mcast-snooping-flood-traffic': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mclag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mclag-icl-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'media-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'member-withdrawal-behavior': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['forward', 'block'], 'type': 'str'},
                'members': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'min-bundle': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['static', 'lacp-passive', 'lacp-active'], 'type': 'str'},
                'p2p-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'packet-sample-rate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'packet-sampler': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disabled', 'enabled'], 'type': 'str'},
                'pause-meter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'pause-meter-resume': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['25%', '50%', '75%'], 'type': 'str'},
                'poe-capable': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'poe-max-power': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'poe-mode-bt-cabable': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'poe-port-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['ieee802-3af', 'ieee802-3at', 'ieee802-3bt'], 'type': 'str'},
                'poe-port-power': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['normal', 'perpetual', 'perpetual-fast'], 'type': 'str'},
                'poe-port-priority': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['critical-priority', 'high-priority', 'low-priority', 'medium-priority'],
                    'type': 'str'
                },
                'poe-pre-standard-detection': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'poe-standard': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'poe-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'port-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'port-number': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'port-owner': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'port-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'port-prefix-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'port-security-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'port-selection-criteria': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['src-mac', 'dst-mac', 'src-dst-mac', 'src-ip', 'dst-ip', 'src-dst-ip'],
                    'type': 'str'
                },
                'ptp-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ptp-status': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'qos-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'restricted-auth-port': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'rpvst-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disabled', 'enabled'], 'type': 'str'},
                'sample-direction': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['rx', 'tx', 'both'], 'type': 'str'},
                'sflow-counter-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'speed': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'auto', '10full', '10half', '100full', '100half', '1000full', '10000full', '1000auto', '40000full', '1000fiber', '10000',
                        '40000', 'auto-module', '100FX-half', '100FX-full', '100000full', '2500full', '25000full', '50000full', '40000auto', '10000cr',
                        '10000sr', '100000sr4', '100000cr4', '25000cr4', '25000sr4', '5000full', '2500auto', '5000auto', '1000full-fiber', '40000sr4',
                        '40000cr4', '25000cr', '25000sr', '50000cr', '50000sr'
                    ],
                    'type': 'str'
                },
                'speed-mask': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'stacking-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['down', 'up'], 'type': 'str'},
                'sticky-mac': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'storm-control-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'stp-bpdu-guard': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disabled', 'enabled'], 'type': 'str'},
                'stp-bpdu-guard-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'stp-root-guard': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disabled', 'enabled'], 'type': 'str'},
                'stp-state': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disabled', 'enabled'], 'type': 'str'},
                'switch-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'trunk-member': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['physical', 'trunk'], 'type': 'str'},
                'untagged-vlans': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'virtual-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'vlan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'igmps-flood-reports': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'igmps-flood-traffic': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'export-tags': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'igmp-snooping': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-mac-event': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pd-capable': {'v_range': [['7.4.4', '']], 'type': 'int'},
                'qnq': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_managedswitch_ports'),
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
