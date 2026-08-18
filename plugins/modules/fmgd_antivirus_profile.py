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
module: fmgd_antivirus_profile
short_description: Configure AntiVirus profiles.
version_added: "1.1.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  vdom:
    description: The parameter (vdom) in requested url.
    type: str
    required: true
  antivirus_profile:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      analytics_accept_filetype:
        aliases: ['analytics-accept-filetype']
        type: list
        elements: str
        description: Only submit files matching this DLP file-pattern to FortiSandbox
      analytics_db:
        aliases: ['analytics-db']
        type: str
        description: Enable/disable using the FortiSandbox signature database to supplement the AV signature databases.
        choices: ['disable', 'enable']
      analytics_ignore_filetype:
        aliases: ['analytics-ignore-filetype']
        type: list
        elements: str
        description: Do not submit files matching this DLP file-pattern to FortiSandbox
      av_block_log:
        aliases: ['av-block-log']
        type: str
        description: Enable/disable logging for AntiVirus file blocking.
        choices: ['disable', 'enable']
      av_virus_log:
        aliases: ['av-virus-log']
        type: str
        description: Enable/disable AntiVirus logging.
        choices: ['disable', 'enable']
      cifs:
        type: dict
        description: Cifs.
        suboptions:
          archive_block:
            aliases: ['archive-block']
            type: list
            elements: str
            description: Select the archive types to block.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout', 'fileslimit']
          archive_log:
            aliases: ['archive-log']
            type: list
            elements: str
            description: Select the archive types to log.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout', 'fileslimit']
          av_scan:
            aliases: ['av-scan']
            type: str
            description: Enable AntiVirus scan service.
            choices: ['disable', 'monitor', 'block']
          emulator:
            type: str
            description: Enable/disable the virus emulator.
            choices: ['disable', 'enable']
          external_blocklist:
            aliases: ['external-blocklist']
            type: str
            description: Enable external-blocklist.
            choices: ['disable', 'monitor', 'block']
          fortindr:
            type: str
            description: Enable scanning of files by FortiNDR.
            choices: ['disable', 'block', 'monitor']
          fortisandbox:
            type: str
            description: Enable scanning of files by FortiSandbox.
            choices: ['disable', 'block', 'monitor']
          outbreak_prevention:
            aliases: ['outbreak-prevention']
            type: str
            description: Enable virus outbreak prevention service.
            choices: ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive']
          quarantine:
            type: str
            description: Enable/disable quarantine for infected files.
            choices: ['disable', 'enable']
          fortiai:
            type: str
            description: Enable/disable scanning of files by FortiAI server.
            choices: ['disable', 'monitor', 'block']
          options:
            type: list
            elements: str
            description: Enable/disable CIFS AntiVirus scanning, monitoring, and quarantine.
            choices: ['scan', 'quarantine', 'avmonitor']
          malware_stream:
            aliases: ['malware-stream']
            type: str
            description: Enable 0-day malware-stream scanning.
            choices: ['disable', 'monitor', 'block']
      comment:
        type: str
        description: Comment.
      content_disarm:
        aliases: ['content-disarm']
        type: dict
        description: Content disarm.
        suboptions:
          cover_page:
            aliases: ['cover-page']
            type: str
            description: Enable/disable inserting a cover page into the disarmed document.
            choices: ['disable', 'enable']
          detect_only:
            aliases: ['detect-only']
            type: str
            description: Enable/disable only detect disarmable files, do not alter content.
            choices: ['disable', 'enable']
          error_action:
            aliases: ['error-action']
            type: str
            description: Action to be taken if CDR engine encounters an unrecoverable error.
            choices: ['block', 'log-only', 'ignore']
          office_action:
            aliases: ['office-action']
            type: str
            description: Enable/disable stripping of PowerPoint action events in Microsoft Office documents.
            choices: ['disable', 'enable']
          office_dde:
            aliases: ['office-dde']
            type: str
            description: Enable/disable stripping of Dynamic Data Exchange events in Microsoft Office documents.
            choices: ['disable', 'enable']
          office_embed:
            aliases: ['office-embed']
            type: str
            description: Enable/disable stripping of embedded objects in Microsoft Office documents.
            choices: ['disable', 'enable']
          office_hylink:
            aliases: ['office-hylink']
            type: str
            description: Enable/disable stripping of hyperlinks in Microsoft Office documents.
            choices: ['disable', 'enable']
          office_linked:
            aliases: ['office-linked']
            type: str
            description: Enable/disable stripping of linked objects in Microsoft Office documents.
            choices: ['disable', 'enable']
          office_macro:
            aliases: ['office-macro']
            type: str
            description: Enable/disable stripping of macros in Microsoft Office documents.
            choices: ['disable', 'enable']
          original_file_destination:
            aliases: ['original-file-destination']
            type: str
            description: Destination to send original file if active content is removed.
            choices: ['fortisandbox', 'quarantine', 'discard']
          pdf_act_form:
            aliases: ['pdf-act-form']
            type: str
            description: Enable/disable stripping of PDF document actions that submit data to other targets.
            choices: ['disable', 'enable']
          pdf_act_gotor:
            aliases: ['pdf-act-gotor']
            type: str
            description: Enable/disable stripping of PDF document actions that access other PDF documents.
            choices: ['disable', 'enable']
          pdf_act_java:
            aliases: ['pdf-act-java']
            type: str
            description: Enable/disable stripping of PDF document actions that execute JavaScript code.
            choices: ['disable', 'enable']
          pdf_act_launch:
            aliases: ['pdf-act-launch']
            type: str
            description: Enable/disable stripping of PDF document actions that launch other applications.
            choices: ['disable', 'enable']
          pdf_act_movie:
            aliases: ['pdf-act-movie']
            type: str
            description: Enable/disable stripping of PDF document actions that play a movie.
            choices: ['disable', 'enable']
          pdf_act_sound:
            aliases: ['pdf-act-sound']
            type: str
            description: Enable/disable stripping of PDF document actions that play a sound.
            choices: ['disable', 'enable']
          pdf_embedfile:
            aliases: ['pdf-embedfile']
            type: str
            description: Enable/disable stripping of embedded files in PDF documents.
            choices: ['disable', 'enable']
          pdf_hyperlink:
            aliases: ['pdf-hyperlink']
            type: str
            description: Enable/disable stripping of hyperlinks from PDF documents.
            choices: ['disable', 'enable']
          pdf_javacode:
            aliases: ['pdf-javacode']
            type: str
            description: Enable/disable stripping of JavaScript code in PDF documents.
            choices: ['disable', 'enable']
          analytics_suspicious:
            aliases: ['analytics-suspicious']
            type: str
            description: Enable/disable using CDR as a secondary method for determining suspicous files for analytics.
            choices: ['disable', 'enable']
      ems_threat_feed:
        aliases: ['ems-threat-feed']
        type: str
        description: Enable/disable use of EMS threat feed when performing AntiVirus scan.
        choices: ['disable', 'enable']
      external_blocklist:
        aliases: ['external-blocklist']
        type: list
        elements: str
        description: One or more external malware block lists.
      external_blocklist_enable_all:
        aliases: ['external-blocklist-enable-all']
        type: str
        description: Enable/disable all external blocklists.
        choices: ['disable', 'enable']
      fortindr_error_action:
        aliases: ['fortindr-error-action']
        type: str
        description: Action to take if FortiNDR encounters an error.
        choices: ['log-only', 'block', 'ignore']
      fortindr_timeout_action:
        aliases: ['fortindr-timeout-action']
        type: str
        description: Action to take if FortiNDR encounters a scan timeout.
        choices: ['log-only', 'block', 'ignore']
      fortisandbox_error_action:
        aliases: ['fortisandbox-error-action']
        type: str
        description: Action to take if FortiSandbox inline scan encounters an error.
        choices: ['log-only', 'block', 'ignore']
      fortisandbox_max_upload:
        aliases: ['fortisandbox-max-upload']
        type: int
        description: Maximum size of files that can be uploaded to FortiSandbox in Mbytes.
      fortisandbox_mode:
        aliases: ['fortisandbox-mode']
        type: str
        description: FortiSandbox scan modes.
        choices: ['inline', 'analytics-suspicious', 'analytics-everything']
      fortisandbox_timeout_action:
        aliases: ['fortisandbox-timeout-action']
        type: str
        description: Action to take if FortiSandbox inline scan encounters a scan timeout.
        choices: ['log-only', 'block', 'ignore']
      ftp:
        type: dict
        description: Ftp.
        suboptions:
          archive_block:
            aliases: ['archive-block']
            type: list
            elements: str
            description: Select the archive types to block.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout', 'fileslimit']
          archive_log:
            aliases: ['archive-log']
            type: list
            elements: str
            description: Select the archive types to log.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout', 'fileslimit']
          av_scan:
            aliases: ['av-scan']
            type: str
            description: Enable AntiVirus scan service.
            choices: ['disable', 'monitor', 'block']
          emulator:
            type: str
            description: Enable/disable the virus emulator.
            choices: ['disable', 'enable']
          external_blocklist:
            aliases: ['external-blocklist']
            type: str
            description: Enable external-blocklist.
            choices: ['disable', 'monitor', 'block']
          fortindr:
            type: str
            description: Enable scanning of files by FortiNDR.
            choices: ['disable', 'block', 'monitor']
          fortisandbox:
            type: str
            description: Enable scanning of files by FortiSandbox.
            choices: ['disable', 'block', 'monitor']
          outbreak_prevention:
            aliases: ['outbreak-prevention']
            type: str
            description: Enable virus outbreak prevention service.
            choices: ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive']
          quarantine:
            type: str
            description: Enable/disable quarantine for infected files.
            choices: ['disable', 'enable']
          fortiai:
            type: str
            description: Enable/disable scanning of files by FortiAI server.
            choices: ['disable', 'monitor', 'block']
          options:
            type: list
            elements: str
            description: Enable/disable FTP AntiVirus scanning, monitoring, and quarantine.
            choices: ['scan', 'quarantine', 'avmonitor']
          malware_stream:
            aliases: ['malware-stream']
            type: str
            description: Enable 0-day malware-stream scanning.
            choices: ['disable', 'monitor', 'block']
      http:
        type: dict
        description: Http.
        suboptions:
          archive_block:
            aliases: ['archive-block']
            type: list
            elements: str
            description: Select the archive types to block.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout', 'fileslimit']
          archive_log:
            aliases: ['archive-log']
            type: list
            elements: str
            description: Select the archive types to log.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout', 'fileslimit']
          av_scan:
            aliases: ['av-scan']
            type: str
            description: Enable AntiVirus scan service.
            choices: ['disable', 'monitor', 'block']
          content_disarm:
            aliases: ['content-disarm']
            type: str
            description: Enable/disable Content Disarm and Reconstruction when performing AntiVirus scan.
            choices: ['disable', 'enable']
          emulator:
            type: str
            description: Enable/disable the virus emulator.
            choices: ['disable', 'enable']
          external_blocklist:
            aliases: ['external-blocklist']
            type: str
            description: Enable external-blocklist.
            choices: ['disable', 'monitor', 'block']
          fortindr:
            type: str
            description: Enable scanning of files by FortiNDR.
            choices: ['disable', 'block', 'monitor']
          fortisandbox:
            type: str
            description: Enable scanning of files by FortiSandbox.
            choices: ['disable', 'block', 'monitor']
          outbreak_prevention:
            aliases: ['outbreak-prevention']
            type: str
            description: Enable virus outbreak prevention service.
            choices: ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive']
          quarantine:
            type: str
            description: Enable/disable quarantine for infected files.
            choices: ['disable', 'enable']
          unknown_content_encoding:
            aliases: ['unknown-content-encoding']
            type: str
            description: Configure the action the FortiGate unit will take on unknown content-encoding.
            choices: ['block', 'inspect', 'bypass']
          fortiai:
            type: str
            description: Enable/disable scanning of files by FortiAI server.
            choices: ['disable', 'monitor', 'block']
          options:
            type: list
            elements: str
            description: Enable/disable HTTP AntiVirus scanning, monitoring, and quarantine.
            choices: ['scan', 'quarantine', 'avmonitor']
          av_optimize:
            aliases: ['av-optimize']
            type: str
            description: Av optimize.
            choices: ['disable', 'enable']
          malware_stream:
            aliases: ['malware-stream']
            type: str
            description: Enable 0-day malware-stream scanning.
            choices: ['disable', 'monitor', 'block']
      imap:
        type: dict
        description: Imap.
        suboptions:
          archive_block:
            aliases: ['archive-block']
            type: list
            elements: str
            description: Select the archive types to block.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout', 'fileslimit']
          archive_log:
            aliases: ['archive-log']
            type: list
            elements: str
            description: Select the archive types to log.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout', 'fileslimit']
          av_scan:
            aliases: ['av-scan']
            type: str
            description: Enable AntiVirus scan service.
            choices: ['disable', 'monitor', 'block']
          content_disarm:
            aliases: ['content-disarm']
            type: str
            description: Enable/disable Content Disarm and Reconstruction when performing AntiVirus scan.
            choices: ['disable', 'enable']
          emulator:
            type: str
            description: Enable/disable the virus emulator.
            choices: ['disable', 'enable']
          executables:
            type: str
            description: Treat Windows executable files as viruses for the purpose of blocking or monitoring.
            choices: ['default', 'virus']
          external_blocklist:
            aliases: ['external-blocklist']
            type: str
            description: Enable external-blocklist.
            choices: ['disable', 'monitor', 'block']
          fortindr:
            type: str
            description: Enable scanning of files by FortiNDR.
            choices: ['disable', 'block', 'monitor']
          fortisandbox:
            type: str
            description: Enable scanning of files by FortiSandbox.
            choices: ['disable', 'block', 'monitor']
          outbreak_prevention:
            aliases: ['outbreak-prevention']
            type: str
            description: Enable virus outbreak prevention service.
            choices: ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive']
          quarantine:
            type: str
            description: Enable/disable quarantine for infected files.
            choices: ['disable', 'enable']
          fortiai:
            type: str
            description: Enable/disable scanning of files by FortiAI server.
            choices: ['disable', 'monitor', 'block']
          options:
            type: list
            elements: str
            description: Enable/disable IMAP AntiVirus scanning, monitoring, and quarantine.
            choices: ['scan', 'quarantine', 'avmonitor']
          malware_stream:
            aliases: ['malware-stream']
            type: str
            description: Enable 0-day malware-stream scanning.
            choices: ['disable', 'monitor', 'block']
      mapi:
        type: dict
        description: Mapi.
        suboptions:
          archive_block:
            aliases: ['archive-block']
            type: list
            elements: str
            description: Select the archive types to block.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout', 'fileslimit']
          archive_log:
            aliases: ['archive-log']
            type: list
            elements: str
            description: Select the archive types to log.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout', 'fileslimit']
          av_scan:
            aliases: ['av-scan']
            type: str
            description: Enable AntiVirus scan service.
            choices: ['disable', 'monitor', 'block']
          emulator:
            type: str
            description: Enable/disable the virus emulator.
            choices: ['disable', 'enable']
          executables:
            type: str
            description: Treat Windows executable files as viruses for the purpose of blocking or monitoring.
            choices: ['default', 'virus']
          external_blocklist:
            aliases: ['external-blocklist']
            type: str
            description: Enable external-blocklist.
            choices: ['disable', 'monitor', 'block']
          fortindr:
            type: str
            description: Enable scanning of files by FortiNDR.
            choices: ['disable', 'block', 'monitor']
          fortisandbox:
            type: str
            description: Enable scanning of files by FortiSandbox.
            choices: ['disable', 'block', 'monitor']
          outbreak_prevention:
            aliases: ['outbreak-prevention']
            type: str
            description: Enable virus outbreak prevention service.
            choices: ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive']
          quarantine:
            type: str
            description: Enable/disable quarantine for infected files.
            choices: ['disable', 'enable']
          fortiai:
            type: str
            description: Enable/disable scanning of files by FortiAI server.
            choices: ['disable', 'monitor', 'block']
          options:
            type: list
            elements: str
            description: Enable/disable MAPI AntiVirus scanning, monitoring, and quarantine.
            choices: ['scan', 'quarantine', 'avmonitor']
          malware_stream:
            aliases: ['malware-stream']
            type: str
            description: Enable 0-day malware-stream scanning.
            choices: ['disable', 'monitor', 'block']
      mobile_malware_db:
        aliases: ['mobile-malware-db']
        type: str
        description: Enable/disable using the mobile malware signature database.
        choices: ['disable', 'enable']
      nac_quar:
        aliases: ['nac-quar']
        type: dict
        description: Nac quar.
        suboptions:
          expiry:
            type: str
            description: Duration of quarantine.
          infected:
            type: str
            description: Enable/Disable quarantining infected hosts to the banned user list.
            choices: ['none', 'quar-src-ip']
          log:
            type: str
            description: Enable/disable AntiVirus quarantine logging.
            choices: ['disable', 'enable']
      name:
        type: str
        description: Profile name.
        required: true
      nntp:
        type: dict
        description: Nntp.
        suboptions:
          archive_block:
            aliases: ['archive-block']
            type: list
            elements: str
            description: Select the archive types to block.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout', 'fileslimit']
          archive_log:
            aliases: ['archive-log']
            type: list
            elements: str
            description: Select the archive types to log.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout', 'fileslimit']
          av_scan:
            aliases: ['av-scan']
            type: str
            description: Enable AntiVirus scan service.
            choices: ['disable', 'monitor', 'block']
          emulator:
            type: str
            description: Enable/disable the virus emulator.
            choices: ['disable', 'enable']
          external_blocklist:
            aliases: ['external-blocklist']
            type: str
            description: Enable external-blocklist.
            choices: ['disable', 'monitor', 'block']
          fortindr:
            type: str
            description: Enable scanning of files by FortiNDR.
            choices: ['disable', 'block', 'monitor']
          fortisandbox:
            type: str
            description: Enable scanning of files by FortiSandbox.
            choices: ['disable', 'block', 'monitor']
          outbreak_prevention:
            aliases: ['outbreak-prevention']
            type: str
            description: Enable virus outbreak prevention service.
            choices: ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive']
          quarantine:
            type: str
            description: Enable/disable quarantine for infected files.
            choices: ['disable', 'enable']
          fortiai:
            type: str
            description: Enable/disable scanning of files by FortiAI server.
            choices: ['disable', 'monitor', 'block']
          options:
            type: list
            elements: str
            description: Enable/disable NNTP AntiVirus scanning, monitoring, and quarantine.
            choices: ['scan', 'quarantine', 'avmonitor']
          malware_stream:
            aliases: ['malware-stream']
            type: str
            description: Enable 0-day malware-stream scanning.
            choices: ['disable', 'monitor', 'block']
      outbreak_prevention_archive_scan:
        aliases: ['outbreak-prevention-archive-scan']
        type: str
        description: Enable/disable outbreak-prevention archive scanning.
        choices: ['disable', 'enable']
      pop3:
        type: dict
        description: Pop3.
        suboptions:
          archive_block:
            aliases: ['archive-block']
            type: list
            elements: str
            description: Select the archive types to block.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout', 'fileslimit']
          archive_log:
            aliases: ['archive-log']
            type: list
            elements: str
            description: Select the archive types to log.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout', 'fileslimit']
          av_scan:
            aliases: ['av-scan']
            type: str
            description: Enable AntiVirus scan service.
            choices: ['disable', 'monitor', 'block']
          content_disarm:
            aliases: ['content-disarm']
            type: str
            description: Enable/disable Content Disarm and Reconstruction when performing AntiVirus scan.
            choices: ['disable', 'enable']
          emulator:
            type: str
            description: Enable/disable the virus emulator.
            choices: ['disable', 'enable']
          executables:
            type: str
            description: Treat Windows executable files as viruses for the purpose of blocking or monitoring.
            choices: ['default', 'virus']
          external_blocklist:
            aliases: ['external-blocklist']
            type: str
            description: Enable external-blocklist.
            choices: ['disable', 'monitor', 'block']
          fortindr:
            type: str
            description: Enable scanning of files by FortiNDR.
            choices: ['disable', 'block', 'monitor']
          fortisandbox:
            type: str
            description: Enable scanning of files by FortiSandbox.
            choices: ['disable', 'block', 'monitor']
          outbreak_prevention:
            aliases: ['outbreak-prevention']
            type: str
            description: Enable virus outbreak prevention service.
            choices: ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive']
          quarantine:
            type: str
            description: Enable/disable quarantine for infected files.
            choices: ['disable', 'enable']
          fortiai:
            type: str
            description: Enable/disable scanning of files by FortiAI server.
            choices: ['disable', 'monitor', 'block']
          options:
            type: list
            elements: str
            description: Enable/disable POP3 AntiVirus scanning, monitoring, and quarantine.
            choices: ['scan', 'quarantine', 'avmonitor']
          malware_stream:
            aliases: ['malware-stream']
            type: str
            description: Enable 0-day malware-stream scanning.
            choices: ['disable', 'monitor', 'block']
      replacemsg_group:
        aliases: ['replacemsg-group']
        type: list
        elements: str
        description: Replacement message group customized for this profile.
      scan_mode:
        aliases: ['scan-mode']
        type: str
        description: Configure scan mode
        choices: ['legacy', 'default', 'full', 'quick']
      smtp:
        type: dict
        description: Smtp.
        suboptions:
          archive_block:
            aliases: ['archive-block']
            type: list
            elements: str
            description: Select the archive types to block.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout', 'fileslimit']
          archive_log:
            aliases: ['archive-log']
            type: list
            elements: str
            description: Select the archive types to log.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout', 'fileslimit']
          av_scan:
            aliases: ['av-scan']
            type: str
            description: Enable AntiVirus scan service.
            choices: ['disable', 'monitor', 'block']
          content_disarm:
            aliases: ['content-disarm']
            type: str
            description: Enable/disable Content Disarm and Reconstruction when performing AntiVirus scan.
            choices: ['disable', 'enable']
          emulator:
            type: str
            description: Enable/disable the virus emulator.
            choices: ['disable', 'enable']
          executables:
            type: str
            description: Treat Windows executable files as viruses for the purpose of blocking or monitoring.
            choices: ['default', 'virus']
          external_blocklist:
            aliases: ['external-blocklist']
            type: str
            description: Enable external-blocklist.
            choices: ['disable', 'monitor', 'block']
          fortindr:
            type: str
            description: Enable scanning of files by FortiNDR.
            choices: ['disable', 'block', 'monitor']
          fortisandbox:
            type: str
            description: Enable scanning of files by FortiSandbox.
            choices: ['disable', 'block', 'monitor']
          outbreak_prevention:
            aliases: ['outbreak-prevention']
            type: str
            description: Enable virus outbreak prevention service.
            choices: ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive']
          quarantine:
            type: str
            description: Enable/disable quarantine for infected files.
            choices: ['disable', 'enable']
          fortiai:
            type: str
            description: Enable/disable scanning of files by FortiAI server.
            choices: ['disable', 'monitor', 'block']
          options:
            type: list
            elements: str
            description: Enable/disable SMTP AntiVirus scanning, monitoring, and quarantine.
            choices: ['scan', 'quarantine', 'avmonitor']
          malware_stream:
            aliases: ['malware-stream']
            type: str
            description: Enable 0-day malware-stream scanning.
            choices: ['disable', 'monitor', 'block']
      ssh:
        type: dict
        description: Ssh.
        suboptions:
          archive_block:
            aliases: ['archive-block']
            type: list
            elements: str
            description: Select the archive types to block.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout', 'fileslimit']
          archive_log:
            aliases: ['archive-log']
            type: list
            elements: str
            description: Select the archive types to log.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout', 'fileslimit']
          av_scan:
            aliases: ['av-scan']
            type: str
            description: Enable AntiVirus scan service.
            choices: ['disable', 'monitor', 'block']
          emulator:
            type: str
            description: Enable/disable the virus emulator.
            choices: ['disable', 'enable']
          external_blocklist:
            aliases: ['external-blocklist']
            type: str
            description: Enable external-blocklist.
            choices: ['disable', 'monitor', 'block']
          fortindr:
            type: str
            description: Enable scanning of files by FortiNDR.
            choices: ['disable', 'block', 'monitor']
          fortisandbox:
            type: str
            description: Enable scanning of files by FortiSandbox.
            choices: ['disable', 'block', 'monitor']
          outbreak_prevention:
            aliases: ['outbreak-prevention']
            type: str
            description: Enable virus outbreak prevention service.
            choices: ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive']
          quarantine:
            type: str
            description: Enable/disable quarantine for infected files.
            choices: ['disable', 'enable']
          fortiai:
            type: str
            description: Enable/disable scanning of files by FortiAI server.
            choices: ['disable', 'monitor', 'block']
          options:
            type: list
            elements: str
            description: Enable/disable SFTP and SCP AntiVirus scanning, monitoring, and quarantine.
            choices: ['avmonitor', 'quarantine', 'scan']
          malware_stream:
            aliases: ['malware-stream']
            type: str
            description: Enable 0-day malware-stream scanning.
            choices: ['disable', 'monitor', 'block']
      feature_set:
        aliases: ['feature-set']
        type: str
        description: Flow/proxy feature set.
        choices: ['proxy', 'flow']
      extended_log:
        aliases: ['extended-log']
        type: str
        description: Enable/disable extended logging for antivirus.
        choices: ['disable', 'enable']
      ftgd_analytics:
        aliases: ['ftgd-analytics']
        type: str
        description: Settings to control which files are uploaded to FortiSandbox.
        choices: ['disable', 'suspicious', 'everything']
      analytics_max_upload:
        aliases: ['analytics-max-upload']
        type: int
        description: Maximum size of files that can be uploaded to FortiSandbox.
      fortiai_error_action:
        aliases: ['fortiai-error-action']
        type: str
        description: Action to take if FortiAI encounters an error.
        choices: ['block', 'log-only', 'ignore']
      fortiai_timeout_action:
        aliases: ['fortiai-timeout-action']
        type: str
        description: Fortiai timeout action.
        choices: ['block', 'log-only', 'ignore']
      external_blocklist_archive_scan:
        aliases: ['external-blocklist-archive-scan']
        type: str
        description: External blocklist archive scan.
        choices: ['disable', 'enable']
      outbreak_prevention:
        aliases: ['outbreak-prevention']
        type: dict
        description: Outbreak prevention.
        suboptions:
          external_blocklist:
            aliases: ['external-blocklist']
            type: str
            description: Enable/disable external malware blocklist.
            choices: ['disable', 'enable']
          ftgd_service:
            aliases: ['ftgd-service']
            type: str
            description: Enable/disable FortiGuard Virus outbreak prevention service.
            choices: ['disable', 'enable']
      analytics_bl_filetype:
        aliases: ['analytics-bl-filetype']
        type: list
        elements: str
        description: Only submit files matching this DLP file-pattern to FortiSandbox.
      analytics_wl_filetype:
        aliases: ['analytics-wl-filetype']
        type: list
        elements: str
        description: Do not submit files matching this DLP file-pattern to FortiSandbox.
      fortisandbox_scan_timeout:
        aliases: ['fortisandbox-scan-timeout']
        type: int
        description: FortiSandbox inline scan timeout in seconds
      websocket:
        type: dict
        description: Websocket.
        suboptions:
          archive_block:
            aliases: ['archive-block']
            type: list
            elements: str
            description: Select the archive types to block.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout']
          archive_log:
            aliases: ['archive-log']
            type: list
            elements: str
            description: Select the archive types to log.
            choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                      'partiallycorrupted', 'timeout']
          av_scan:
            aliases: ['av-scan']
            type: str
            description: Enable/disable AntiVirus scan service.
            choices: ['disable', 'block', 'monitor']
          emulator:
            type: str
            description: Enable/disable the virus emulator.
            choices: ['disable', 'enable']
          external_blocklist:
            aliases: ['external-blocklist']
            type: str
            description: Enable/disable external-blocklist.
            choices: ['disable', 'block', 'monitor']
          fortindr:
            type: str
            description: Enable/disable scanning of files by FortiNDR.
            choices: ['disable', 'block', 'monitor']
          fortisandbox:
            type: str
            description: Enable/disable scanning of files by FortiSandbox.
            choices: ['disable', 'block', 'monitor']
          malware_stream:
            aliases: ['malware-stream']
            type: str
            description: Enable/disable 0-day malware-stream scanning.
            choices: ['disable', 'block', 'monitor']
          outbreak_prevention:
            aliases: ['outbreak-prevention']
            type: str
            description: Enable/disable virus outbreak prevention service.
            choices: ['disable', 'block', 'monitor']
          quarantine:
            type: str
            description: Enable/disable quarantine for infected files.
            choices: ['disable', 'enable']
      analytics_ignore_mpip:
        aliases: ['analytics-ignore-mpip']
        type: list
        elements: str
        description: Do not submit files matching this DLP label to FortiSandbox
      fabric_force_sync:
        aliases: ['fabric-force-sync']
        type: str
        description: Enable/disable forced synchronization of configuration objects from the root FortiGate unit to the downstream devices.
        choices: ['disable', 'enable']
      fabric_object:
        aliases: ['fabric-object']
        type: str
        description: Security Fabric global object setting.
        choices: ['disable', 'enable']
      fabric_object_source:
        aliases: ['fabric-object-source']
        type: str
        description: Source of truth for fabric object.
        choices: ['member', 'local', 'root']
      fortisandbox_destination:
        aliases: ['fortisandbox-destination']
        type: str
        description: FortiSandbox destination options.
        choices: ['auto', 'sandbox', 'sandbox-cloud']
      outbreak_prevention_error_action:
        aliases: ['outbreak-prevention-error-action']
        type: str
        description: Action to take if outbreak-prevention encounters an error
        choices: ['block', 'log-only', 'ignore']
      outbreak_prevention_timeout_action:
        aliases: ['outbreak-prevention-timeout-action']
        type: str
        description: Action to take if outbreak-prevention encounters a request timeout
        choices: ['block', 'log-only', 'ignore']
      uuid:
        type: str
        description: Universally Unique Identifier
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure AntiVirus profiles.
      fortinet.fmgdevice.fmgd_antivirus_profile:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        antivirus_profile:
          name: "your value" # Required variable, string
          # analytics_accept_filetype: <list or string>
          # analytics_db: <value in [disable, enable]>
          # analytics_ignore_filetype: <list or string>
          # av_block_log: <value in [disable, enable]>
          # av_virus_log: <value in [disable, enable]>
          # cifs:
          #   archive_block: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                   "unhandled", "partiallycorrupted", "timeout", "fileslimit"]
          #   archive_log: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                 "unhandled", "partiallycorrupted", "timeout", "fileslimit"]
          #   av_scan: <value in [disable, monitor, block]>
          #   emulator: <value in [disable, enable]>
          #   external_blocklist: <value in [disable, monitor, block]>
          #   fortindr: <value in [disable, block, monitor]>
          #   fortisandbox: <value in [disable, block, monitor]>
          #   outbreak_prevention: <value in [disable, block, monitor, ...]>
          #   quarantine: <value in [disable, enable]>
          #   fortiai: <value in [disable, monitor, block]>
          #   options: ["scan", "quarantine", "avmonitor"]
          #   malware_stream: <value in [disable, monitor, block]>
          # comment: <string>
          # content_disarm:
          #   cover_page: <value in [disable, enable]>
          #   detect_only: <value in [disable, enable]>
          #   error_action: <value in [block, log-only, ignore]>
          #   office_action: <value in [disable, enable]>
          #   office_dde: <value in [disable, enable]>
          #   office_embed: <value in [disable, enable]>
          #   office_hylink: <value in [disable, enable]>
          #   office_linked: <value in [disable, enable]>
          #   office_macro: <value in [disable, enable]>
          #   original_file_destination: <value in [fortisandbox, quarantine, discard]>
          #   pdf_act_form: <value in [disable, enable]>
          #   pdf_act_gotor: <value in [disable, enable]>
          #   pdf_act_java: <value in [disable, enable]>
          #   pdf_act_launch: <value in [disable, enable]>
          #   pdf_act_movie: <value in [disable, enable]>
          #   pdf_act_sound: <value in [disable, enable]>
          #   pdf_embedfile: <value in [disable, enable]>
          #   pdf_hyperlink: <value in [disable, enable]>
          #   pdf_javacode: <value in [disable, enable]>
          #   analytics_suspicious: <value in [disable, enable]>
          # ems_threat_feed: <value in [disable, enable]>
          # external_blocklist: <list or string>
          # external_blocklist_enable_all: <value in [disable, enable]>
          # fortindr_error_action: <value in [log-only, block, ignore]>
          # fortindr_timeout_action: <value in [log-only, block, ignore]>
          # fortisandbox_error_action: <value in [log-only, block, ignore]>
          # fortisandbox_max_upload: <integer>
          # fortisandbox_mode: <value in [inline, analytics-suspicious, analytics-everything]>
          # fortisandbox_timeout_action: <value in [log-only, block, ignore]>
          # ftp:
          #   archive_block: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                   "unhandled", "partiallycorrupted", "timeout", "fileslimit"]
          #   archive_log: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                 "unhandled", "partiallycorrupted", "timeout", "fileslimit"]
          #   av_scan: <value in [disable, monitor, block]>
          #   emulator: <value in [disable, enable]>
          #   external_blocklist: <value in [disable, monitor, block]>
          #   fortindr: <value in [disable, block, monitor]>
          #   fortisandbox: <value in [disable, block, monitor]>
          #   outbreak_prevention: <value in [disable, block, monitor, ...]>
          #   quarantine: <value in [disable, enable]>
          #   fortiai: <value in [disable, monitor, block]>
          #   options: ["scan", "quarantine", "avmonitor"]
          #   malware_stream: <value in [disable, monitor, block]>
          # http:
          #   archive_block: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                   "unhandled", "partiallycorrupted", "timeout", "fileslimit"]
          #   archive_log: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                 "unhandled", "partiallycorrupted", "timeout", "fileslimit"]
          #   av_scan: <value in [disable, monitor, block]>
          #   content_disarm: <value in [disable, enable]>
          #   emulator: <value in [disable, enable]>
          #   external_blocklist: <value in [disable, monitor, block]>
          #   fortindr: <value in [disable, block, monitor]>
          #   fortisandbox: <value in [disable, block, monitor]>
          #   outbreak_prevention: <value in [disable, block, monitor, ...]>
          #   quarantine: <value in [disable, enable]>
          #   unknown_content_encoding: <value in [block, inspect, bypass]>
          #   fortiai: <value in [disable, monitor, block]>
          #   options: ["scan", "quarantine", "avmonitor"]
          #   av_optimize: <value in [disable, enable]>
          #   malware_stream: <value in [disable, monitor, block]>
          # imap:
          #   archive_block: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                   "unhandled", "partiallycorrupted", "timeout", "fileslimit"]
          #   archive_log: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                 "unhandled", "partiallycorrupted", "timeout", "fileslimit"]
          #   av_scan: <value in [disable, monitor, block]>
          #   content_disarm: <value in [disable, enable]>
          #   emulator: <value in [disable, enable]>
          #   executables: <value in [default, virus]>
          #   external_blocklist: <value in [disable, monitor, block]>
          #   fortindr: <value in [disable, block, monitor]>
          #   fortisandbox: <value in [disable, block, monitor]>
          #   outbreak_prevention: <value in [disable, block, monitor, ...]>
          #   quarantine: <value in [disable, enable]>
          #   fortiai: <value in [disable, monitor, block]>
          #   options: ["scan", "quarantine", "avmonitor"]
          #   malware_stream: <value in [disable, monitor, block]>
          # mapi:
          #   archive_block: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                   "unhandled", "partiallycorrupted", "timeout", "fileslimit"]
          #   archive_log: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                 "unhandled", "partiallycorrupted", "timeout", "fileslimit"]
          #   av_scan: <value in [disable, monitor, block]>
          #   emulator: <value in [disable, enable]>
          #   executables: <value in [default, virus]>
          #   external_blocklist: <value in [disable, monitor, block]>
          #   fortindr: <value in [disable, block, monitor]>
          #   fortisandbox: <value in [disable, block, monitor]>
          #   outbreak_prevention: <value in [disable, block, monitor, ...]>
          #   quarantine: <value in [disable, enable]>
          #   fortiai: <value in [disable, monitor, block]>
          #   options: ["scan", "quarantine", "avmonitor"]
          #   malware_stream: <value in [disable, monitor, block]>
          # mobile_malware_db: <value in [disable, enable]>
          # nac_quar:
          #   expiry: <string>
          #   infected: <value in [none, quar-src-ip]>
          #   log: <value in [disable, enable]>
          # nntp:
          #   archive_block: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                   "unhandled", "partiallycorrupted", "timeout", "fileslimit"]
          #   archive_log: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                 "unhandled", "partiallycorrupted", "timeout", "fileslimit"]
          #   av_scan: <value in [disable, monitor, block]>
          #   emulator: <value in [disable, enable]>
          #   external_blocklist: <value in [disable, monitor, block]>
          #   fortindr: <value in [disable, block, monitor]>
          #   fortisandbox: <value in [disable, block, monitor]>
          #   outbreak_prevention: <value in [disable, block, monitor, ...]>
          #   quarantine: <value in [disable, enable]>
          #   fortiai: <value in [disable, monitor, block]>
          #   options: ["scan", "quarantine", "avmonitor"]
          #   malware_stream: <value in [disable, monitor, block]>
          # outbreak_prevention_archive_scan: <value in [disable, enable]>
          # pop3:
          #   archive_block: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                   "unhandled", "partiallycorrupted", "timeout", "fileslimit"]
          #   archive_log: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                 "unhandled", "partiallycorrupted", "timeout", "fileslimit"]
          #   av_scan: <value in [disable, monitor, block]>
          #   content_disarm: <value in [disable, enable]>
          #   emulator: <value in [disable, enable]>
          #   executables: <value in [default, virus]>
          #   external_blocklist: <value in [disable, monitor, block]>
          #   fortindr: <value in [disable, block, monitor]>
          #   fortisandbox: <value in [disable, block, monitor]>
          #   outbreak_prevention: <value in [disable, block, monitor, ...]>
          #   quarantine: <value in [disable, enable]>
          #   fortiai: <value in [disable, monitor, block]>
          #   options: ["scan", "quarantine", "avmonitor"]
          #   malware_stream: <value in [disable, monitor, block]>
          # replacemsg_group: <list or string>
          # scan_mode: <value in [legacy, default, full, ...]>
          # smtp:
          #   archive_block: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                   "unhandled", "partiallycorrupted", "timeout", "fileslimit"]
          #   archive_log: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                 "unhandled", "partiallycorrupted", "timeout", "fileslimit"]
          #   av_scan: <value in [disable, monitor, block]>
          #   content_disarm: <value in [disable, enable]>
          #   emulator: <value in [disable, enable]>
          #   executables: <value in [default, virus]>
          #   external_blocklist: <value in [disable, monitor, block]>
          #   fortindr: <value in [disable, block, monitor]>
          #   fortisandbox: <value in [disable, block, monitor]>
          #   outbreak_prevention: <value in [disable, block, monitor, ...]>
          #   quarantine: <value in [disable, enable]>
          #   fortiai: <value in [disable, monitor, block]>
          #   options: ["scan", "quarantine", "avmonitor"]
          #   malware_stream: <value in [disable, monitor, block]>
          # ssh:
          #   archive_block: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                   "unhandled", "partiallycorrupted", "timeout", "fileslimit"]
          #   archive_log: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                 "unhandled", "partiallycorrupted", "timeout", "fileslimit"]
          #   av_scan: <value in [disable, monitor, block]>
          #   emulator: <value in [disable, enable]>
          #   external_blocklist: <value in [disable, monitor, block]>
          #   fortindr: <value in [disable, block, monitor]>
          #   fortisandbox: <value in [disable, block, monitor]>
          #   outbreak_prevention: <value in [disable, block, monitor, ...]>
          #   quarantine: <value in [disable, enable]>
          #   fortiai: <value in [disable, monitor, block]>
          #   options: ["avmonitor", "quarantine", "scan"]
          #   malware_stream: <value in [disable, monitor, block]>
          # feature_set: <value in [proxy, flow]>
          # extended_log: <value in [disable, enable]>
          # ftgd_analytics: <value in [disable, suspicious, everything]>
          # analytics_max_upload: <integer>
          # fortiai_error_action: <value in [block, log-only, ignore]>
          # fortiai_timeout_action: <value in [block, log-only, ignore]>
          # external_blocklist_archive_scan: <value in [disable, enable]>
          # outbreak_prevention:
          #   external_blocklist: <value in [disable, enable]>
          #   ftgd_service: <value in [disable, enable]>
          # analytics_bl_filetype: <list or string>
          # analytics_wl_filetype: <list or string>
          # fortisandbox_scan_timeout: <integer>
          # websocket:
          #   archive_block: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                   "unhandled", "partiallycorrupted", "timeout"]
          #   archive_log: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                 "unhandled", "partiallycorrupted", "timeout"]
          #   av_scan: <value in [disable, block, monitor]>
          #   emulator: <value in [disable, enable]>
          #   external_blocklist: <value in [disable, block, monitor]>
          #   fortindr: <value in [disable, block, monitor]>
          #   fortisandbox: <value in [disable, block, monitor]>
          #   malware_stream: <value in [disable, block, monitor]>
          #   outbreak_prevention: <value in [disable, block, monitor]>
          #   quarantine: <value in [disable, enable]>
          # analytics_ignore_mpip: <list or string>
          # fabric_force_sync: <value in [disable, enable]>
          # fabric_object: <value in [disable, enable]>
          # fabric_object_source: <value in [member, local, root]>
          # fortisandbox_destination: <value in [auto, sandbox, sandbox-cloud]>
          # outbreak_prevention_error_action: <value in [block, log-only, ignore]>
          # outbreak_prevention_timeout_action: <value in [block, log-only, ignore]>
          # uuid: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/antivirus/profile'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'antivirus_profile': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'analytics-accept-filetype': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'analytics-db': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'analytics-ignore-filetype': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'av-block-log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'av-virus-log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cifs': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'
                            ],
                            'elements': 'str'
                        },
                        'av-scan': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'emulator': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'outbreak-prevention': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive'],
                            'type': 'str'
                        },
                        'quarantine': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortiai': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'options': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']],
                            'type': 'list',
                            'choices': ['scan', 'quarantine', 'avmonitor'],
                            'elements': 'str'
                        },
                        'malware-stream': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
                    }
                },
                'comment': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'content-disarm': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'cover-page': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'detect-only': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'error-action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['block', 'log-only', 'ignore'], 'type': 'str'},
                        'office-action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'office-dde': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'office-embed': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'office-hylink': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'office-linked': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'office-macro': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'original-file-destination': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['fortisandbox', 'quarantine', 'discard'],
                            'type': 'str'
                        },
                        'pdf-act-form': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pdf-act-gotor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pdf-act-java': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pdf-act-launch': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pdf-act-movie': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pdf-act-sound': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pdf-embedfile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pdf-hyperlink': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pdf-javacode': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'analytics-suspicious': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'ems-threat-feed': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'external-blocklist': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'external-blocklist-enable-all': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortindr-error-action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['log-only', 'block', 'ignore'], 'type': 'str'},
                'fortindr-timeout-action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['log-only', 'block', 'ignore'], 'type': 'str'},
                'fortisandbox-error-action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['log-only', 'block', 'ignore'], 'type': 'str'},
                'fortisandbox-max-upload': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'fortisandbox-mode': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['inline', 'analytics-suspicious', 'analytics-everything'],
                    'type': 'str'
                },
                'fortisandbox-timeout-action': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['log-only', 'block', 'ignore'],
                    'type': 'str'
                },
                'ftp': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'
                            ],
                            'elements': 'str'
                        },
                        'av-scan': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'emulator': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'outbreak-prevention': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive'],
                            'type': 'str'
                        },
                        'quarantine': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortiai': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'options': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']],
                            'type': 'list',
                            'choices': ['scan', 'quarantine', 'avmonitor'],
                            'elements': 'str'
                        },
                        'malware-stream': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
                    }
                },
                'http': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'
                            ],
                            'elements': 'str'
                        },
                        'av-scan': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'content-disarm': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'emulator': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'outbreak-prevention': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive'],
                            'type': 'str'
                        },
                        'quarantine': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'unknown-content-encoding': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['block', 'inspect', 'bypass'],
                            'type': 'str'
                        },
                        'fortiai': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'options': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']],
                            'type': 'list',
                            'choices': ['scan', 'quarantine', 'avmonitor'],
                            'elements': 'str'
                        },
                        'av-optimize': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'malware-stream': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
                    }
                },
                'imap': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'
                            ],
                            'elements': 'str'
                        },
                        'av-scan': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'content-disarm': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'emulator': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'executables': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['default', 'virus'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'outbreak-prevention': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive'],
                            'type': 'str'
                        },
                        'quarantine': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortiai': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'options': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']],
                            'type': 'list',
                            'choices': ['scan', 'quarantine', 'avmonitor'],
                            'elements': 'str'
                        },
                        'malware-stream': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
                    }
                },
                'mapi': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'
                            ],
                            'elements': 'str'
                        },
                        'av-scan': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'emulator': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'executables': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['default', 'virus'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'outbreak-prevention': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive'],
                            'type': 'str'
                        },
                        'quarantine': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortiai': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'options': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']],
                            'type': 'list',
                            'choices': ['scan', 'quarantine', 'avmonitor'],
                            'elements': 'str'
                        },
                        'malware-stream': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
                    }
                },
                'mobile-malware-db': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nac-quar': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'expiry': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'infected': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'quar-src-ip'], 'type': 'str'},
                        'log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'nntp': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'
                            ],
                            'elements': 'str'
                        },
                        'av-scan': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'emulator': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'outbreak-prevention': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive'],
                            'type': 'str'
                        },
                        'quarantine': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortiai': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'options': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']],
                            'type': 'list',
                            'choices': ['scan', 'quarantine', 'avmonitor'],
                            'elements': 'str'
                        },
                        'malware-stream': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
                    }
                },
                'outbreak-prevention-archive-scan': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pop3': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'
                            ],
                            'elements': 'str'
                        },
                        'av-scan': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'content-disarm': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'emulator': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'executables': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['default', 'virus'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'outbreak-prevention': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive'],
                            'type': 'str'
                        },
                        'quarantine': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortiai': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'options': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']],
                            'type': 'list',
                            'choices': ['scan', 'quarantine', 'avmonitor'],
                            'elements': 'str'
                        },
                        'malware-stream': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
                    }
                },
                'replacemsg-group': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'scan-mode': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['legacy', 'default', 'full', 'quick'], 'type': 'str'},
                'smtp': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'
                            ],
                            'elements': 'str'
                        },
                        'av-scan': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'content-disarm': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'emulator': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'executables': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['default', 'virus'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'outbreak-prevention': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive'],
                            'type': 'str'
                        },
                        'quarantine': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortiai': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'options': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']],
                            'type': 'list',
                            'choices': ['scan', 'quarantine', 'avmonitor'],
                            'elements': 'str'
                        },
                        'malware-stream': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
                    }
                },
                'ssh': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'
                            ],
                            'elements': 'str'
                        },
                        'av-scan': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'emulator': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'outbreak-prevention': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive'],
                            'type': 'str'
                        },
                        'quarantine': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortiai': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'options': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']],
                            'type': 'list',
                            'choices': ['avmonitor', 'quarantine', 'scan'],
                            'elements': 'str'
                        },
                        'malware-stream': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
                    }
                },
                'feature-set': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['proxy', 'flow'], 'type': 'str'},
                'extended-log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ftgd-analytics': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'suspicious', 'everything'], 'type': 'str'},
                'analytics-max-upload': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'fortiai-error-action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['block', 'log-only', 'ignore'], 'type': 'str'},
                'fortiai-timeout-action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['block', 'log-only', 'ignore'], 'type': 'str'},
                'external-blocklist-archive-scan': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'outbreak-prevention': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']],
                    'type': 'dict',
                    'options': {
                        'external-blocklist': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ftgd-service': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'analytics-bl-filetype': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'type': 'list', 'elements': 'str'},
                'analytics-wl-filetype': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'type': 'list', 'elements': 'str'},
                'fortisandbox-scan-timeout': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'websocket': {
                    'v_range': [['7.6.7', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['7.6.7', '']],
                            'type': 'list',
                            'choices': ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout'],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['7.6.7', '']],
                            'type': 'list',
                            'choices': ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout'],
                            'elements': 'str'
                        },
                        'av-scan': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'emulator': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'malware-stream': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'outbreak-prevention': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'quarantine': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'analytics-ignore-mpip': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'fabric-force-sync': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object-source': {'v_range': [['8.0.0', '']], 'choices': ['member', 'local', 'root'], 'type': 'str'},
                'fortisandbox-destination': {'v_range': [['8.0.0', '']], 'choices': ['auto', 'sandbox', 'sandbox-cloud'], 'type': 'str'},
                'outbreak-prevention-error-action': {'v_range': [['8.0.0', '']], 'choices': ['block', 'log-only', 'ignore'], 'type': 'str'},
                'outbreak-prevention-timeout-action': {'v_range': [['8.0.0', '']], 'choices': ['block', 'log-only', 'ignore'], 'type': 'str'},
                'uuid': {'v_range': [['8.0.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'antivirus_profile'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
