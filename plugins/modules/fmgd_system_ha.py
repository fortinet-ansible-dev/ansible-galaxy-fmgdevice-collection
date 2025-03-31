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
module: fmgd_system_ha
short_description: Configure HA.
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
    system_ha:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            arps:
                type: int
                description: Number of gratuitous ARPs
            arps_interval:
                aliases: ['arps-interval']
                type: int
                description: Time between gratuitous ARPs
            authentication:
                type: str
                description: Enable/disable heartbeat message authentication.
                choices:
                    - 'disable'
                    - 'enable'
            board_failover_tolerance:
                aliases: ['board-failover-tolerance']
                type: int
                description: Worker board failure failover threshold.
            chassis_id:
                aliases: ['chassis-id']
                type: int
                description: Chassis id
            cpu_threshold:
                aliases: ['cpu-threshold']
                type: str
                description: Dynamic weighted load balancing CPU usage weight and high and low thresholds.
            encryption:
                type: str
                description: Enable/disable heartbeat message encryption.
                choices:
                    - 'disable'
                    - 'enable'
            evpn_ttl:
                aliases: ['evpn-ttl']
                type: int
                description: HA EVPN FDB TTL on primary box
            failover_hold_time:
                aliases: ['failover-hold-time']
                type: int
                description: Time to wait before failover
            ftp_proxy_threshold:
                aliases: ['ftp-proxy-threshold']
                type: str
                description: Dynamic weighted load balancing weight and high and low number of FTP proxy sessions.
            gratuitous_arps:
                aliases: ['gratuitous-arps']
                type: str
                description: Enable/disable gratuitous ARPs.
                choices:
                    - 'disable'
                    - 'enable'
            group_id:
                aliases: ['group-id']
                type: int
                description: HA group ID
            group_name:
                aliases: ['group-name']
                type: str
                description: Cluster group name.
            ha_direct:
                aliases: ['ha-direct']
                type: str
                description: Enable/disable using ha-mgmt interface for syslog, remote authentication
                choices:
                    - 'disable'
                    - 'enable'
            ha_eth_type:
                aliases: ['ha-eth-type']
                type: str
                description: HA heartbeat packet Ethertype
            ha_mgmt_interfaces:
                aliases: ['ha-mgmt-interfaces']
                type: list
                elements: dict
                description: Ha mgmt interfaces.
                suboptions:
                    dst:
                        type: list
                        elements: str
                        description: Default route destination for reserved HA management interface.
                    gateway:
                        type: str
                        description: Default route gateway for reserved HA management interface.
                    gateway6:
                        type: str
                        description: Default IPv6 gateway for reserved HA management interface.
                    id:
                        type: int
                        description: Table ID.
                    interface:
                        type: list
                        elements: str
                        description: Interface to reserve for HA management.
            ha_mgmt_status:
                aliases: ['ha-mgmt-status']
                type: str
                description: Enable to reserve interfaces to manage individual cluster units.
                choices:
                    - 'disable'
                    - 'enable'
            ha_port_dtag_mode:
                aliases: ['ha-port-dtag-mode']
                type: str
                description: HA port double-tagging mode.
                choices:
                    - 'proprietary'
                    - 'double-tagging'
            ha_port_outer_tpid:
                aliases: ['ha-port-outer-tpid']
                type: str
                description: Set HA port outer tpid.
                choices:
                    - '0x8100'
                    - '0x88a8'
                    - '0x9100'
            ha_uptime_diff_margin:
                aliases: ['ha-uptime-diff-margin']
                type: int
                description: Normally you would only reduce this value for failover testing.
            hb_interval:
                aliases: ['hb-interval']
                type: int
                description: Time between sending heartbeat packets
            hb_interval_in_milliseconds:
                aliases: ['hb-interval-in-milliseconds']
                type: str
                description: Units of heartbeat interval time between sending heartbeat packets.
                choices:
                    - '100ms'
                    - '10ms'
            hb_lost_threshold:
                aliases: ['hb-lost-threshold']
                type: int
                description: Number of lost heartbeats to signal a failure
            hbdev:
                type: str
                description: Heartbeat interfaces.
            hbdev_second_vlan_id:
                aliases: ['hbdev-second-vlan-id']
                type: int
                description: Second VLAN id to use for HA heartbeat
            hbdev_vlan_id:
                aliases: ['hbdev-vlan-id']
                type: int
                description: VLAN id to use for HA heartbeat
            hc_eth_type:
                aliases: ['hc-eth-type']
                type: str
                description: Transparent mode HA heartbeat packet Ethertype
            hello_holddown:
                aliases: ['hello-holddown']
                type: int
                description: Time to wait before changing from hello to work state
            http_proxy_threshold:
                aliases: ['http-proxy-threshold']
                type: str
                description: Dynamic weighted load balancing weight and high and low number of HTTP proxy sessions.
            hw_session_hold_time:
                aliases: ['hw-session-hold-time']
                type: int
                description: Time to hold sessions before purging on secondary node
            hw_session_sync_delay:
                aliases: ['hw-session-sync-delay']
                type: int
                description: Time to wait before session sync starts on primary node
            hw_session_sync_dev:
                aliases: ['hw-session-sync-dev']
                type: list
                elements: str
                description: Hardware session sync interface.
            imap_proxy_threshold:
                aliases: ['imap-proxy-threshold']
                type: str
                description: Dynamic weighted load balancing weight and high and low number of IMAP proxy sessions.
            ipsec_phase2_proposal:
                aliases: ['ipsec-phase2-proposal']
                type: list
                elements: str
                description: IPsec phase2 proposal.
                choices:
                    - 'aes128-sha1'
                    - 'aes128-sha256'
                    - 'aes128-sha384'
                    - 'aes128-sha512'
                    - 'aes192-sha1'
                    - 'aes192-sha256'
                    - 'aes192-sha384'
                    - 'aes192-sha512'
                    - 'aes256-sha1'
                    - 'aes256-sha256'
                    - 'aes256-sha384'
                    - 'aes256-sha512'
                    - 'aes128gcm'
                    - 'aes256gcm'
                    - 'chacha20poly1305'
            key:
                type: list
                elements: str
                description: Key.
            l2ep_eth_type:
                aliases: ['l2ep-eth-type']
                type: str
                description: Telnet session HA heartbeat packet Ethertype
            link_failed_signal:
                aliases: ['link-failed-signal']
                type: str
                description: Enable to shut down all interfaces for 1 sec after a failover.
                choices:
                    - 'disable'
                    - 'enable'
            load_balance_all:
                aliases: ['load-balance-all']
                type: str
                description: Enable to load balance TCP sessions.
                choices:
                    - 'disable'
                    - 'enable'
            logical_sn:
                aliases: ['logical-sn']
                type: str
                description: Enable/disable usage of the logical serial number.
                choices:
                    - 'disable'
                    - 'enable'
            memory_based_failover:
                aliases: ['memory-based-failover']
                type: str
                description: Enable/disable memory based failover.
                choices:
                    - 'disable'
                    - 'enable'
            memory_compatible_mode:
                aliases: ['memory-compatible-mode']
                type: str
                description: Enable/disable memory compatible mode.
                choices:
                    - 'disable'
                    - 'enable'
            memory_failover_flip_timeout:
                aliases: ['memory-failover-flip-timeout']
                type: int
                description: Time to wait between subsequent memory based failovers in minutes
            memory_failover_monitor_period:
                aliases: ['memory-failover-monitor-period']
                type: int
                description: Duration of high memory usage before memory based failover is triggered in seconds
            memory_failover_sample_rate:
                aliases: ['memory-failover-sample-rate']
                type: int
                description: Rate at which memory usage is sampled in order to measure memory usage in seconds
            memory_failover_threshold:
                aliases: ['memory-failover-threshold']
                type: int
                description: Memory usage threshold to trigger memory based failover
            memory_threshold:
                aliases: ['memory-threshold']
                type: str
                description: Dynamic weighted load balancing memory usage weight and high and low thresholds.
            mode:
                type: str
                description: HA mode.
                choices:
                    - 'standalone'
                    - 'a-a'
                    - 'a-p'
                    - 'config-sync-only'
                    - 'active-passive'
            monitor:
                type: list
                elements: str
                description: Interfaces to check for port monitoring
            multicast_ttl:
                aliases: ['multicast-ttl']
                type: int
                description: HA multicast TTL on primary
            nntp_proxy_threshold:
                aliases: ['nntp-proxy-threshold']
                type: str
                description: Dynamic weighted load balancing weight and high and low number of NNTP proxy sessions.
            override:
                type: str
                description: Enable and increase the priority of the unit that should always be primary
                choices:
                    - 'disable'
                    - 'enable'
            override_wait_time:
                aliases: ['override-wait-time']
                type: int
                description: Delay negotiating if override is enabled
            password:
                type: list
                elements: str
                description: Cluster password.
            pingserver_failover_threshold:
                aliases: ['pingserver-failover-threshold']
                type: int
                description: Remote IP monitoring failover threshold
            pingserver_flip_timeout:
                aliases: ['pingserver-flip-timeout']
                type: int
                description: Time to wait in minutes before renegotiating after a remote IP monitoring failover.
            pingserver_monitor_interface:
                aliases: ['pingserver-monitor-interface']
                type: list
                elements: str
                description: Interfaces to check for remote IP monitoring.
            pingserver_secondary_force_reset:
                aliases: ['pingserver-secondary-force-reset']
                type: str
                description: Enable to force the cluster to negotiate after a remote IP monitoring failover.
                choices:
                    - 'disable'
                    - 'enable'
            pop3_proxy_threshold:
                aliases: ['pop3-proxy-threshold']
                type: str
                description: Dynamic weighted load balancing weight and high and low number of POP3 proxy sessions.
            priority:
                type: int
                description: Increase the priority to select the primary unit
            route_hold:
                aliases: ['route-hold']
                type: int
                description: Time to wait between routing table updates to the cluster
            route_ttl:
                aliases: ['route-ttl']
                type: int
                description: TTL for primary unit routes
            route_wait:
                aliases: ['route-wait']
                type: int
                description: Time to wait before sending new routes to the cluster
            schedule:
                type: str
                description: Type of A-A load balancing.
                choices:
                    - 'none'
                    - 'hub'
                    - 'leastconnection'
                    - 'round-robin'
                    - 'weight-round-robin'
                    - 'random'
                    - 'ip'
                    - 'ipport'
            session_pickup:
                aliases: ['session-pickup']
                type: str
                description: Enable/disable session pickup.
                choices:
                    - 'disable'
                    - 'enable'
            session_pickup_connectionless:
                aliases: ['session-pickup-connectionless']
                type: str
                description: Enable/disable UDP and ICMP session sync.
                choices:
                    - 'disable'
                    - 'enable'
            session_pickup_delay:
                aliases: ['session-pickup-delay']
                type: str
                description: Enable to sync sessions longer than 30 sec.
                choices:
                    - 'disable'
                    - 'enable'
            session_pickup_expectation:
                aliases: ['session-pickup-expectation']
                type: str
                description: Enable/disable session helper expectation session sync for FGSP.
                choices:
                    - 'disable'
                    - 'enable'
            session_pickup_nat:
                aliases: ['session-pickup-nat']
                type: str
                description: Enable/disable NAT session sync for FGSP.
                choices:
                    - 'disable'
                    - 'enable'
            session_sync_dev:
                aliases: ['session-sync-dev']
                type: list
                elements: str
                description: Offload session-sync process to kernel and sync sessions using connected interface
            smtp_proxy_threshold:
                aliases: ['smtp-proxy-threshold']
                type: str
                description: Dynamic weighted load balancing weight and high and low number of SMTP proxy sessions.
            ssd_failover:
                aliases: ['ssd-failover']
                type: str
                description: Enable/disable automatic HA failover on SSD disk failure.
                choices:
                    - 'disable'
                    - 'enable'
            standalone_config_sync:
                aliases: ['standalone-config-sync']
                type: str
                description: Enable/disable FGSP configuration synchronization.
                choices:
                    - 'disable'
                    - 'enable'
            standalone_mgmt_vdom:
                aliases: ['standalone-mgmt-vdom']
                type: str
                description: Enable/disable standalone management VDOM.
                choices:
                    - 'disable'
                    - 'enable'
            sync_config:
                aliases: ['sync-config']
                type: str
                description: Enable/disable configuration synchronization.
                choices:
                    - 'disable'
                    - 'enable'
            sync_packet_balance:
                aliases: ['sync-packet-balance']
                type: str
                description: Enable/disable HA packet distribution to multiple CPUs.
                choices:
                    - 'disable'
                    - 'enable'
            unicast_gateway:
                aliases: ['unicast-gateway']
                type: str
                description: Default route gateway for unicast interface.
            unicast_hb:
                aliases: ['unicast-hb']
                type: str
                description: Enable/disable unicast heartbeat.
                choices:
                    - 'disable'
                    - 'enable'
            unicast_hb_netmask:
                aliases: ['unicast-hb-netmask']
                type: str
                description: Unicast heartbeat netmask.
            unicast_hb_peerip:
                aliases: ['unicast-hb-peerip']
                type: str
                description: Unicast heartbeat peer IP.
            unicast_peers:
                aliases: ['unicast-peers']
                type: list
                elements: dict
                description: Unicast peers.
                suboptions:
                    id:
                        type: int
                        description: Table ID.
                    peer_ip:
                        aliases: ['peer-ip']
                        type: str
                        description: Unicast peer IP.
            unicast_status:
                aliases: ['unicast-status']
                type: str
                description: Enable/disable unicast connection.
                choices:
                    - 'disable'
                    - 'enable'
            uninterruptible_primary_wait:
                aliases: ['uninterruptible-primary-wait']
                type: int
                description: Number of minutes the primary HA unit waits before the secondary HA unit is considered upgraded and the system is started ...
            upgrade_mode:
                aliases: ['upgrade-mode']
                type: str
                description: The mode to upgrade a cluster.
                choices:
                    - 'simultaneous'
                    - 'uninterruptible'
                    - 'local-only'
                    - 'secondary-only'
            vcluster:
                type: list
                elements: dict
                description: Vcluster.
                suboptions:
                    monitor:
                        type: list
                        elements: str
                        description: Interfaces to check for port monitoring
                    override:
                        type: str
                        description: Enable and increase the priority of the unit that should always be primary
                        choices:
                            - 'disable'
                            - 'enable'
                    override_wait_time:
                        aliases: ['override-wait-time']
                        type: int
                        description: Delay negotiating if override is enabled
                    pingserver_failover_threshold:
                        aliases: ['pingserver-failover-threshold']
                        type: int
                        description: Remote IP monitoring failover threshold
                    pingserver_flip_timeout:
                        aliases: ['pingserver-flip-timeout']
                        type: int
                        description: Time to wait in minutes before renegotiating after a remote IP monitoring failover.
                    pingserver_monitor_interface:
                        aliases: ['pingserver-monitor-interface']
                        type: list
                        elements: str
                        description: Interfaces to check for remote IP monitoring.
                    pingserver_secondary_force_reset:
                        aliases: ['pingserver-secondary-force-reset']
                        type: str
                        description: Enable to force the cluster to negotiate after a remote IP monitoring failover.
                        choices:
                            - 'disable'
                            - 'enable'
                    priority:
                        type: int
                        description: Increase the priority to select the primary unit
                    vcluster_id:
                        aliases: ['vcluster-id']
                        type: int
                        description: ID.
                    vdom:
                        type: list
                        elements: str
                        description: Virtual domain
                    pingserver_slave_force_reset:
                        aliases: ['pingserver-slave-force-reset']
                        type: str
                        description: Pingserver slave force reset.
                        choices:
                            - 'disable'
                            - 'enable'
            vcluster_status:
                aliases: ['vcluster-status']
                type: str
                description: Enable/disable virtual cluster for virtual clustering.
                choices:
                    - 'disable'
                    - 'enable'
            weight:
                type: list
                elements: str
                description: Weight-round-robin weight for each cluster unit.
            pingserver_slave_force_reset:
                aliases: ['pingserver-slave-force-reset']
                type: str
                description: Enable to force the cluster to negotiate after a remote IP monitoring failover.
                choices:
                    - 'disable'
                    - 'enable'
            uninterruptible_upgrade:
                aliases: ['uninterruptible-upgrade']
                type: str
                description: Enable to upgrade a cluster without blocking network traffic.
                choices:
                    - 'disable'
                    - 'enable'
            vdom:
                type: list
                elements: str
                description: VDOMs in virtual cluster 1.
            minimum_worker_threshold:
                aliases: ['minimum-worker-threshold']
                type: int
                description: The minimum number of operating workers to cause a content clustering chassis failover.
            vcluster2:
                type: str
                description: Enable/disable virtual cluster 2 for virtual clustering.
                choices:
                    - 'disable'
                    - 'enable'
            secondary_vcluster:
                aliases: ['secondary-vcluster']
                type: dict
                description: Secondary vcluster.
                suboptions:
                    monitor:
                        type: list
                        elements: str
                        description: Interfaces to check for port monitoring
                    override:
                        type: str
                        description: Enable and increase the priority of the unit that should always be primary.
                        choices:
                            - 'disable'
                            - 'enable'
                    override_wait_time:
                        aliases: ['override-wait-time']
                        type: int
                        description: Delay negotiating if override is enabled
                    pingserver_failover_threshold:
                        aliases: ['pingserver-failover-threshold']
                        type: int
                        description: Remote IP monitoring failover threshold
                    pingserver_monitor_interface:
                        aliases: ['pingserver-monitor-interface']
                        type: list
                        elements: str
                        description: Interfaces to check for remote IP monitoring.
                    pingserver_secondary_force_reset:
                        aliases: ['pingserver-secondary-force-reset']
                        type: str
                        description: Enable to force the cluster to negotiate after a remote IP monitoring failover.
                        choices:
                            - 'disable'
                            - 'enable'
                    priority:
                        type: int
                        description: Increase the priority to select the primary unit
                    vcluster_id:
                        aliases: ['vcluster-id']
                        type: int
                        description: Vcluster id.
                    vdom:
                        type: list
                        elements: str
                        description: VDOMs in virtual cluster 2.
                    pingserver_slave_force_reset:
                        aliases: ['pingserver-slave-force-reset']
                        type: str
                        description: Enable to force the cluster to negotiate after a remote IP monitoring failover.
                        choices:
                            - 'disable'
                            - 'enable'
            secondary_switch_standby:
                aliases: ['secondary-switch-standby']
                type: str
                description: Enable to force content clustering subordinate unit standby mode.
                choices:
                    - 'disable'
                    - 'enable'
            vcluster_id:
                aliases: ['vcluster-id']
                type: int
                description: Vcluster id.
            slave_switch_standby:
                aliases: ['slave-switch-standby']
                type: str
                description: Enable to force content clustering subordinate unit standby mode.
                choices:
                    - 'disable'
                    - 'enable'
            frup:
                type: str
                description: Enable/disable Fortinet Redundant UTM Protocol
                choices:
                    - 'disable'
                    - 'enable'
            frup_settings:
                aliases: ['frup-settings']
                type: dict
                description: Frup settings.
                suboptions:
                    active_interface:
                        aliases: ['active-interface']
                        type: list
                        elements: str
                        description: FRUP active interface
                    active_switch_port:
                        aliases: ['active-switch-port']
                        type: str
                        description: FRUP active switch port list
                        choices:
                            - '1'
                            - '2'
                            - '3'
                            - '4'
                            - '5'
                            - '6'
                            - '7'
                            - '8'
                            - '9'
                            - '10'
                            - '11'
                            - '12'
                            - '13'
                            - '14'
                            - '15'
                            - '16'
                            - '17'
                            - '18'
                            - '19'
                            - '20'
                            - '21'
                            - '22'
                            - '23'
                            - '24'
                            - '25'
                            - '26'
                            - '27'
                            - '28'
                            - '29'
                            - '30'
                            - '31'
                            - '32'
                            - '33'
                            - '34'
                            - '35'
                            - '36'
                            - '37'
                            - '38'
                            - '39'
                            - '40'
                            - '41'
                            - '42'
                            - '43'
                            - '44'
                            - '45'
                            - '46'
                            - '47'
                            - '48'
                            - '49'
                            - '50'
                            - '51'
                            - '52'
                            - '53'
                            - '54'
                            - '55'
                            - '56'
                            - '57'
                            - '58'
                            - '59'
                            - '60'
                            - '61'
                            - '62'
                            - '63'
                            - '64'
                            - '65'
                            - '66'
                            - '67'
                            - '68'
                            - '69'
                            - '70'
                            - '71'
                            - '72'
                            - '73'
                            - '74'
                            - '75'
                            - '76'
                            - '77'
                            - '78'
                            - '79'
                            - '80'
                            - '81'
                            - '82'
                            - '83'
                            - '84'
                    backup_interface:
                        aliases: ['backup-interface']
                        type: list
                        elements: str
                        description: FRUP backup interface
            inter_cluster_session_sync:
                aliases: ['inter-cluster-session-sync']
                type: str
                description: Enable/disable synchronization of sessions among HA clusters.
                choices:
                    - 'disable'
                    - 'enable'
            auto_virtual_mac_interface:
                aliases: ['auto-virtual-mac-interface']
                type: list
                elements: str
                description: The physical interface that will be assigned an auto-generated virtual MAC address.
            backup_hbdev:
                aliases: ['backup-hbdev']
                type: list
                elements: str
                description: Backup heartbeat interfaces.
            check_secondary_dev_health:
                aliases: ['check-secondary-dev-health']
                type: str
                description: Enable/disable secondary dev health check for session load-balance in HA A-A mode.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Configure HA.
      fortinet.fmgdevice.fmgd_system_ha:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        system_ha:
          # arps: <integer>
          # arps_interval: <integer>
          # authentication: <value in [disable, enable]>
          # board_failover_tolerance: <integer>
          # chassis_id: <integer>
          # cpu_threshold: <string>
          # encryption: <value in [disable, enable]>
          # evpn_ttl: <integer>
          # failover_hold_time: <integer>
          # ftp_proxy_threshold: <string>
          # gratuitous_arps: <value in [disable, enable]>
          # group_id: <integer>
          # group_name: <string>
          # ha_direct: <value in [disable, enable]>
          # ha_eth_type: <string>
          # ha_mgmt_interfaces:
          #   - dst: <list or string>
          #     gateway: <string>
          #     gateway6: <string>
          #     id: <integer>
          #     interface: <list or string>
          # ha_mgmt_status: <value in [disable, enable]>
          # ha_port_dtag_mode: <value in [proprietary, double-tagging]>
          # ha_port_outer_tpid: <value in [0x8100, 0x88a8, 0x9100]>
          # ha_uptime_diff_margin: <integer>
          # hb_interval: <integer>
          # hb_interval_in_milliseconds: <value in [100ms, 10ms]>
          # hb_lost_threshold: <integer>
          # hbdev: <string>
          # hbdev_second_vlan_id: <integer>
          # hbdev_vlan_id: <integer>
          # hc_eth_type: <string>
          # hello_holddown: <integer>
          # http_proxy_threshold: <string>
          # hw_session_hold_time: <integer>
          # hw_session_sync_delay: <integer>
          # hw_session_sync_dev: <list or string>
          # imap_proxy_threshold: <string>
          # ipsec_phase2_proposal:
          #   - "aes128-sha1"
          #   - "aes128-sha256"
          #   - "aes128-sha384"
          #   - "aes128-sha512"
          #   - "aes192-sha1"
          #   - "aes192-sha256"
          #   - "aes192-sha384"
          #   - "aes192-sha512"
          #   - "aes256-sha1"
          #   - "aes256-sha256"
          #   - "aes256-sha384"
          #   - "aes256-sha512"
          #   - "aes128gcm"
          #   - "aes256gcm"
          #   - "chacha20poly1305"
          # key: <list or string>
          # l2ep_eth_type: <string>
          # link_failed_signal: <value in [disable, enable]>
          # load_balance_all: <value in [disable, enable]>
          # logical_sn: <value in [disable, enable]>
          # memory_based_failover: <value in [disable, enable]>
          # memory_compatible_mode: <value in [disable, enable]>
          # memory_failover_flip_timeout: <integer>
          # memory_failover_monitor_period: <integer>
          # memory_failover_sample_rate: <integer>
          # memory_failover_threshold: <integer>
          # memory_threshold: <string>
          # mode: <value in [standalone, a-a, a-p, ...]>
          # monitor: <list or string>
          # multicast_ttl: <integer>
          # nntp_proxy_threshold: <string>
          # override: <value in [disable, enable]>
          # override_wait_time: <integer>
          # password: <list or string>
          # pingserver_failover_threshold: <integer>
          # pingserver_flip_timeout: <integer>
          # pingserver_monitor_interface: <list or string>
          # pingserver_secondary_force_reset: <value in [disable, enable]>
          # pop3_proxy_threshold: <string>
          # priority: <integer>
          # route_hold: <integer>
          # route_ttl: <integer>
          # route_wait: <integer>
          # schedule: <value in [none, hub, leastconnection, ...]>
          # session_pickup: <value in [disable, enable]>
          # session_pickup_connectionless: <value in [disable, enable]>
          # session_pickup_delay: <value in [disable, enable]>
          # session_pickup_expectation: <value in [disable, enable]>
          # session_pickup_nat: <value in [disable, enable]>
          # session_sync_dev: <list or string>
          # smtp_proxy_threshold: <string>
          # ssd_failover: <value in [disable, enable]>
          # standalone_config_sync: <value in [disable, enable]>
          # standalone_mgmt_vdom: <value in [disable, enable]>
          # sync_config: <value in [disable, enable]>
          # sync_packet_balance: <value in [disable, enable]>
          # unicast_gateway: <string>
          # unicast_hb: <value in [disable, enable]>
          # unicast_hb_netmask: <string>
          # unicast_hb_peerip: <string>
          # unicast_peers:
          #   - id: <integer>
          #     peer_ip: <string>
          # unicast_status: <value in [disable, enable]>
          # uninterruptible_primary_wait: <integer>
          # upgrade_mode: <value in [simultaneous, uninterruptible, local-only, ...]>
          # vcluster:
          #   - monitor: <list or string>
          #     override: <value in [disable, enable]>
          #     override_wait_time: <integer>
          #     pingserver_failover_threshold: <integer>
          #     pingserver_flip_timeout: <integer>
          #     pingserver_monitor_interface: <list or string>
          #     pingserver_secondary_force_reset: <value in [disable, enable]>
          #     priority: <integer>
          #     vcluster_id: <integer>
          #     vdom: <list or string>
          #     pingserver_slave_force_reset: <value in [disable, enable]>
          # vcluster_status: <value in [disable, enable]>
          # weight: <list or string>
          # pingserver_slave_force_reset: <value in [disable, enable]>
          # uninterruptible_upgrade: <value in [disable, enable]>
          # vdom: <list or string>
          # minimum_worker_threshold: <integer>
          # vcluster2: <value in [disable, enable]>
          # secondary_vcluster:
          #   monitor: <list or string>
          #   override: <value in [disable, enable]>
          #   override_wait_time: <integer>
          #   pingserver_failover_threshold: <integer>
          #   pingserver_monitor_interface: <list or string>
          #   pingserver_secondary_force_reset: <value in [disable, enable]>
          #   priority: <integer>
          #   vcluster_id: <integer>
          #   vdom: <list or string>
          #   pingserver_slave_force_reset: <value in [disable, enable]>
          # secondary_switch_standby: <value in [disable, enable]>
          # vcluster_id: <integer>
          # slave_switch_standby: <value in [disable, enable]>
          # frup: <value in [disable, enable]>
          # frup_settings:
          #   active_interface: <list or string>
          #   active_switch_port: <value in [1, 2, 3, ...]>
          #   backup_interface: <list or string>
          # inter_cluster_session_sync: <value in [disable, enable]>
          # auto_virtual_mac_interface: <list or string>
          # backup_hbdev: <list or string>
          # check_secondary_dev_health: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/system/ha'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_ha': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'arps': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'arps-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'authentication': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'board-failover-tolerance': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'chassis-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'cpu-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'encryption': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'evpn-ttl': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'failover-hold-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ftp-proxy-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'gratuitous-arps': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'group-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'group-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ha-direct': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ha-eth-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ha-mgmt-interfaces': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'dst': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'gateway': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'gateway6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'ha-mgmt-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ha-port-dtag-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['proprietary', 'double-tagging'], 'type': 'str'},
                'ha-port-outer-tpid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['0x8100', '0x88a8', '0x9100'], 'type': 'str'},
                'ha-uptime-diff-margin': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'hb-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'hb-interval-in-milliseconds': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['100ms', '10ms'], 'type': 'str'},
                'hb-lost-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'hbdev': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'hbdev-second-vlan-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'hbdev-vlan-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'hc-eth-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'hello-holddown': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'http-proxy-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'hw-session-hold-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'hw-session-sync-delay': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'hw-session-sync-dev': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'imap-proxy-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ipsec-phase2-proposal': {
                    'v_range': [['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'aes128-sha1', 'aes128-sha256', 'aes128-sha384', 'aes128-sha512', 'aes192-sha1', 'aes192-sha256', 'aes192-sha384',
                        'aes192-sha512', 'aes256-sha1', 'aes256-sha256', 'aes256-sha384', 'aes256-sha512', 'aes128gcm', 'aes256gcm', 'chacha20poly1305'
                    ],
                    'elements': 'str'
                },
                'key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'l2ep-eth-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'link-failed-signal': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'load-balance-all': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'logical-sn': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'memory-based-failover': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'memory-compatible-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'memory-failover-flip-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'memory-failover-monitor-period': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'memory-failover-sample-rate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'memory-failover-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'memory-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'mode': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['standalone', 'a-a', 'a-p', 'config-sync-only', 'active-passive'],
                    'type': 'str'
                },
                'monitor': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'multicast-ttl': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'nntp-proxy-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'override': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-wait-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'pingserver-failover-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'pingserver-flip-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'pingserver-monitor-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'pingserver-secondary-force-reset': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pop3-proxy-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'route-hold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'route-ttl': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'route-wait': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'schedule': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['none', 'hub', 'leastconnection', 'round-robin', 'weight-round-robin', 'random', 'ip', 'ipport'],
                    'type': 'str'
                },
                'session-pickup': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'session-pickup-connectionless': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'session-pickup-delay': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'session-pickup-expectation': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'session-pickup-nat': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'session-sync-dev': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'smtp-proxy-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ssd-failover': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'standalone-config-sync': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'standalone-mgmt-vdom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sync-config': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sync-packet-balance': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'unicast-gateway': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'unicast-hb': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'unicast-hb-netmask': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'unicast-hb-peerip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'unicast-peers': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'peer-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'unicast-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uninterruptible-primary-wait': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'upgrade-mode': {
                    'v_range': [['7.4.3', '']],
                    'choices': ['simultaneous', 'uninterruptible', 'local-only', 'secondary-only'],
                    'type': 'str'
                },
                'vcluster': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'monitor': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'override': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'override-wait-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'pingserver-failover-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'pingserver-flip-timeout': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'pingserver-monitor-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'pingserver-secondary-force-reset': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'vcluster-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'vdom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'pingserver-slave-force-reset': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'vcluster-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'pingserver-slave-force-reset': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uninterruptible-upgrade': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vdom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'minimum-worker-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'vcluster2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'secondary-vcluster': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'monitor': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'override': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'override-wait-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'pingserver-failover-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'pingserver-monitor-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'pingserver-secondary-force-reset': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'vcluster-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'vdom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'pingserver-slave-force-reset': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'secondary-switch-standby': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vcluster-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'slave-switch-standby': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'frup': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'frup-settings': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'active-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'active-switch-port': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': [
                                '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21',
                                '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41',
                                '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61',
                                '62', '63', '64', '65', '66', '67', '68', '69', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '80', '81',
                                '82', '83', '84'
                            ],
                            'type': 'str'
                        },
                        'backup-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    }
                },
                'inter-cluster-session-sync': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auto-virtual-mac-interface': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'},
                'backup-hbdev': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'},
                'check-secondary-dev-health': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_ha'),
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
