# CS-Aggressor-Kit

Homemade Aggressor scripts kit for Cobalt Strike

<p align="center">
  <img width="450" height="450" src="/Pictures/logo.png"><br /><br />
  <img alt="GitHub License" src="https://img.shields.io/github/license/nickvourd/CS-Aggressor-Kit?style=social&logo=GitHub&logoColor=purple">
  <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/nickvourd/CS-Aggressor-Kit?logoColor=yellow"><br />
  <img alt="GitHub forks" src="https://img.shields.io/github/forks/nickvourd/CS-Aggressor-Kit?logoColor=red">
  <img alt="GitHub watchers" src="https://img.shields.io/github/watchers/nickvourd/CS-Aggressor-Kit?logoColor=blue">
  <img alt="GitHub contributors" src="https://img.shields.io/github/contributors/nickvourd/CS-Aggressor-Kit?style=social&logo=GitHub&logoColor=green">
</p>

## Description

This repository contains numerous CNA files (Aggressor Scripts) for Cobalt Strike, which are useful during a Red Team engagement. Many of these CNA files have been inspired by other well-known repositories.

This project created with ❤️ by [@nickvourd](https://x.com/nickvourd).

Special thanks to [Will Nowlan](https://www.linkedin.com/in/will-nowlan-87b18a1bb/) for all his contributions.

## Table of Contents
- [CS-Aggressor-Kit](#cs-aggressor-kit)
  - [Description](#description)
  - [Table of Contents](#table-of-contents)
  - [Summary](#summary)
  - [Alert](#alert)
    - [Setup Slack and Webhooks](#setup-slack-and-webhooks)
    - [Setup Discord and Webhooks](#setup-discord-and-webhooks)
    - [Setup Teams Webhooks](#setup-teams-webhooks)
    - [Setup Mattermost Webhooks](#setup-mattermost-webhooks)
    - [Set Up iMessage Implementation](#set-up-imessage-implementation)
    - [Set Up Signal Implementation](#set-up-signal-implementation)
    - [Alert CNA Output Examples](#alert-cna-output-examples)
      - [New incoming Beacon notification example (Slack)](#new-incoming-beacon-notification-example-slack)
      - [New Web hit notification example (Discord)](#new-web-hit-notification-example-discord)
      - [New CS client connects to the teamserver notification example (Slack)](#new-cs-client-connects-to-the-teamserver-notification-example-slack)
      - [CS Client disconnects from the teamserver notification example (Discord)](#cs-client-disconnects-from-the-teamserver-notification-example-discord)
      - [CS Client hosts a file or clones a website notification example (Slack)](#cs-client-hosts-a-file-or-clones-a-website-notification-example-slack)
      - [CS client posts something in the event log (Discord)](#cs-client-posts-something-in-the-event-log-discord)
      - [New credentials come in from keylogging (Discord)](#new-credentials-come-in-from-keylogging-discord)
      - [New screenshot is taken from Cobalt Strike (Slack)](#new-screenshot-is-taken-from-cobalt-strike-slack)
  - [Auto](#auto)
    - [How Auto Sleep Works](#how-auto-sleep-works)
    - [Auto Sleep Interactive For Testing](#auto-sleep-interactive-for-testing)
    - [Auto Sleep After Initial Access](#auto-sleep-after-initial-access)
  - [Misc](#misc)
    - [Beacon Name Tab Example](#beacon-name-tab-example)
    - [Beacon Name Tab Colors Example](#beacon-name-tab-colors-example)
    - [CS All Tabs Bold Example](#cs-all-tabs-bold-example)
    - [CWD Beacon Bar Example](#cwd-beacon-bar-example)
    - [Opsec Example](#opsec-example)
  - [SA](#sa)
    - [File Color Example](#file-color-example)
    - [Process Color Example](#process-color-example)
  - [Utils](#utils)
    - [Sonata Examples](#sonata-examples)
      - [Sonata File](#sonata-file)
      - [Sonata String](#sonata-string)
    - [Locate Example](#locate-example)

## Summary

The following table illustrates all the CNA files included in this project:

| Section | Name | Description |
|:-----------:|:-----------:|:-----------:|
| Alert |[slack-alerts_linux.cna](/Alert/Slack/slack-alerts_linux.cna)| Slack CNA file for Linux CS client |
| Alert |[slack-alerts_windows.cna](/Alert/Slack/slack-alerts_windows.cna)| Slack CNA file for Windows CS client |
| Alert |[discord-alerts_linux.cna](/Alert/Discord/discord-alerts_linux.cna)| Discord CNA file for Linux CS Client |
| Alert |[teams-alerts_linux.cna](/Alert/Teams/teams-alerts_linux.cna)| Teams CNA file for Linux CS Client |
| Alert |[mattermost-alerts_linux.cna](/Alert/Mattermost/mattermost-alerts_linux.cna)| Mattermost CNA file for Linux CS Client |
| Alert |[mattermost-alerts_windows.cna](/Alert/Mattermost/mattermost-alerts_windows.cna)| Mattermost CNA file for Windows CS Client |
| Alert | [iMessage_MacOS.cna](/Alert/iMessage/iMessage_MacOS.cna) | iMessage CNA file for MacOS CS Client | 
| Alert | [Signal_linux.cna](/Alert/Signal/Signal_linux.cna) | Signal CNA file for Linux/MacOS CS Client | 
| Auto | [auto-sleep-on-start.cna](/Auto/auto-sleep-on-start.cna) | This CNA file automatically sets the sleep time to a specific value when a new user joins the teamserver. It requires a client to remain open at all times, ensuring the sleep time is configured even if the Cobalt Strike client is closed or you forget to set it while away |
| Auto | [auto-sleep-on-exit.cna](/Auto/auto-sleep-on-exit.cna) | This CNA file automatically sets the sleep time to a specific value when all users, except one, disconnect from the teamserver. A client must remain open at all times |
| Auto | [auto-sleep-after-initial-access.cna](/Auto/auto-sleep-after-initial-access.cna) | This CNA file automatically configures the beacon's sleep interval upon initial acccess | 
| Auto | [auto-sleep-interactive-for-testing.cna](/Auto/auto-sleep-interactive-for-testing.cna) | This CNA file automatically set beacon sleep to 0 on initial connection |
| Misc | [Beacon-Name-Tab.cna](/Misc/Beacon-Name-Tab.cna) | This CNA file modifies the Beacon tab name format from the default to `username`@`hostname` (`pid`) |
| Misc | [Beacon-Name-Tab-Colors.cna](/Misc/Beacon-Name-Tab-Colors.cna) | This CNA file modifies the Beacon tab name format from the default to `username`@`hostname` (`pid`), for admin's beacon the color is red, for user's beacon the color is green |
| Misc | [CS-All-Tabs-Bold.cna](/Misc/CS-All-Tabs-Bold.cna) | This CNA file makes all CS client tabs bold |
| Misc | [CWD-Beacon-Bar.cna](/Misc/CWD-Beacon-Bar.cna) | This CNA file enhances Beacon console status bar to display the Beacon's last known working directory path. Additionally, improves the 'cd' command to support restoring the previous directory path seamlessly (Usage: `cd -`) |
| SA | [File-Color.cna](/SA/File-Color.cna) | This CNA file outputs files in a colorful format for file hunting |
| SA | [PS-Color.cna](/SA/PS-Color.cna) | This CNA file outputs proccess in a colorful format for process hunting |
| Utils | [Sonata.cna](/Utils/Sonata.cna) | This CNA file is a port of the [Sonata](https://github.com/nickvourd/Sonata) tool. Sonata is a file hash calculator that supports MD5, SHA1, SHA256, and SHA512 algorithms. The CNA port enhances functionality by supporting string hash calculations as well |
| Utils | [locate.cna](/Utils/locate.cna) | This CNA functions like the `locate` Linux command. Additionally, it performs case-insensitive keyword searches. This CNA requires a Linux CS client |

## Alert

These CNA files will notify you via the `Slack`/`Discord`/`Teams`/`Mattermost`/`Signal`/`iMessage` applications when:

- A new client connects to the team server.
- A CS client disconnects from the team server.
- A new incoming beacon.
- A new web hit occurs.
- A CS client posts something in the event log.
- New site hosts.
- New credentials come in from keylogging.
- A new screenshot is taken from Cobalt Strike.

:information_source: Some CNA files are compatible with Windows/Linux/MacOS operating systems.

The following table illustrates the CNA files included in the Alert section:

| Name | OS | App | Description |
|:-----------:|:-----------:|:-----------:|:-----------:|
|[slack-alerts_linux.cna](/Alert/Slack/slack-alerts_linux.cna)| MacOS/Linux | Slack | Slack CNA file for Linux CS client |
|[slack-alerts_windows.cna](/Alert/Slack/slack-alerts_windows.cna)| Windows | Slack | Slack CNA file for Windows CS client |
|[discord-alerts_linux.cna](/Alert/Discord/discord-alerts_linux.cna)| MacOS/Linux | Discord | Discord CNA file for Linux CS Client |
|[teams-alerts_linux.cna](/Alert/Teams/teams-alerts_linux.cna)| MacOS/Linux | Teams | Teams CNA file for Linux CS Client |
|[mattermost-alerts_linux.cna](/Alert/Mattermost/mattermost-alerts_linux.cna)| MacOS/Linux | Mattermost | Mattermost CNA file for Linux CS Client |
|[mattermost-alerts_windows.cna](/Alert/Mattermost/mattermost-alerts_windows.cna)| Windows | Mattermost | Mattermost CNA file for Windows CS Client |
| [iMessage_MacOS.cna](/Alert/iMessage/iMessage_MacOS.cna) | MacOS | Apple iMessage | iMessage CNA file for MacOS CS Client | 
| [Signal_linux.cna](/Alert/Signal/Signal_linux.cna) | MacOS/Linux | Signal | Signal CNA file for Linux/MacOS CS Client | 

### Setup Slack and Webhooks

:information_source: To set up a Slack server and webhook, you can follow these guides provided on the [Slack website](https://api.slack.com/incoming-webhooks).

### Setup Discord and Webhooks

:information_source: To set up a Discord server and webhook, you can follow these guides provided on the [Discord website](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks).

### Setup Teams Webhooks

:information_source: To set up a Microsoft Teams webhook, you can follow these guides provided on [Microsoft website](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=newteams%2Cdotnet).

### Setup Mattermost Webhooks

:information_source: To set up a Mattermost webhook, you can follow these guides provided on [Mattermost website](https://developers.mattermost.com/integrate/webhooks/incoming/).

### Set Up iMessage Implementation

:information_source: To set up the iMessage implementation, you need to use a device with MacOS like Macbook Pro/Air or Mac mini. 

- Install:

```
brew install osascript
```

### Set Up Signal Implementation

-> Full Digram Communication:

```
+------------------------------+
| Linux Host                   |
|                              |
|  Cobalt Strike / CNA Script  |
|        (runs as root)        |
|               |              |
|     curl http://127.0.0.1:8080
|               |              |
+---------------|--------------+
                |
    Host port 8080 mapped to container port 8080
                |
+---------------v--------------+
| Docker Container (signal)    |
|  Process user: signal-api    |
|  signal-cli REST API (8080)  |
+------------------------------+
```

:information_source: In order to set up signal implementation, you need to do the following.

- Install [Docker Desktop](https://docs.docker.com/desktop/)
- Install docker signal-cli:

```
docker run -d \
  --name signal \
  -p 8080:8080 \
  -v signal-data:/home/.local/share/signal-cli \
  bbernhard/signal-cli-rest-api
```

- Then connect:

```
docker exec -it signal bash   
```

- Visit [Captcha Website](https://signalcaptchas.org/registration/generate.html)
- Solve the captcha and you will see the following:

![signal-token](/Pictures/signal-token.png)

![signal-token-2](/Pictures/signal-token-2.png)

- Switch to user:

```
su - signal-api
```

- Register your number:

```
signal-cli --config /home/.local/share/signal-cli -u <+your_number> register --captcha 'signalcaptcha://<LONG_TOKEN_VALUE>'
```

- Verify the number using the SMS code:

```
signal-cli --config /home/.local/share/signal-cli -u <+your_number> verify <verify_code>
```

- Then set your profile name:

```
signal-cli --config /home/.local/share/signal-cli -u <+your_number> updateProfile --name '<C2_BOT_NAME>' --about '<Description>'
```

- From outside the container send a test message:

```
curl -X POST http://127.0.0.1:8080/v2/send \
  -H "Content-Type: application/json" \
  -d '{
    "number": "<+your_number>",
    "recipients": ["<+receipt_number>"],
    "message": "Test from Signal CLI REST API"
  }'
```

### Alert CNA Output Examples

#### New incoming Beacon notification example (Slack):

![New-Beacon-Example](/Pictures/New-Beacon-Example1.png)

#### New Web hit notification example (Discord):

![Web-Hit-Example](/Pictures/Web-Hit-Example1.png)

#### New CS client connects to the teamserver notification example (Slack):

![New-CS-Client-Connect-Example](/Pictures/New-CS-Client-Connect-Example1.png)

#### CS Client disconnects from the teamserver notification example (Discord):

![CS-Client-Disconnect](/Pictures/CS-Client-Disconnect.png)

#### CS Client hosts a file or clones a website notification example (Slack):

![Host-File-Clone-Site](/Pictures/Host-File-Clone-Site.png)

#### CS client posts something in the event log (Discord):

![New-message-CS](/Pictures/New-message-CS.png)

#### New credentials come in from keylogging (Discord):

![New-credentials-come-in](/Pictures/Keystrokes-Received.png)

#### New screenshot is taken from Cobalt Strike (Slack):

![New-Screesnhot-taken](/Pictures/New-Screesnhot-taken.png)

## Auto

These CNA files automatically configure certain actions in Cobalt Strike.

The following table illustrates the CNA files included in the Auto section:

| Name | Description |
|:-----------:|:-----------:|
| [auto-sleep-on-start.cna](/Auto/auto-sleep-on-start.cna) | This CNA file automatically sets the sleep time to a specific value when a new user joins the teamserver. It requires a client to remain open at all times |
| [auto-sleep-on-exit.cna](/Auto/auto-sleep-on-exit.cna) | This CNA file automatically sets the sleep time to a specific value when all users, except one, disconnect from the teamserver. A client must remain open at all times |
| [auto-sleep-interactive-for-testing.cna](/Auto/auto-sleep-interactive-for-testing.cna) | This CNA file automatically set beacon sleep to 0 on initial connection |
| [auto-sleep-after-initial-access.cna](/Auto/auto-sleep-after-initial-access.cna) | This CNA file automatically configures the beacon's sleep interval upon initial acccess |

### How Auto Sleep Works

:information_source: The two auto-sleep CNA files can be used individually or together, depending on your preferences.

**Diagram 1**: The two Cobalt Srike clients are connected to the Team server.

![Diagram-1](/Pictures/Diagram-1.png)

**Diagram 2**: At the end of the day's engagement tasks, the operators decide to stop the engagement. One operator, using a Cobalt Strike client without the CNA file, disconnects from the teamserver, while the other operator ensures his/her Cobalt Strike client with the CNA file ([auto-sleep-on-exit.cna](/Auto/auto-sleep-on-exit.cna)) remains open.

![Diagram-2](/Pictures/Diagram-2.png)

**Diagram 3**: The Cobalt Strike client with the CNA file will detect the user disconnection event and automatically adjust the sleep time to the predefined value specified in the CNA file.

![Diagram-3](/Pictures/Diagram-3.png)

**Diagram 4**: The next day, when the operator (with the Cobalt Strike client without the CNA file) connects to the Team Server, the always-open client with the loaded CNA file ([auto-sleep-on-start.cna](/Auto/auto-sleep-on-start.cna)) will detect the new user connection. It will then automatically set the sleep time to the predefined value specified in the CNA file.

![Diagram-4](/Pictures/Diagram-4.png)

### Auto Sleep Interactive For Testing

This CNA file automatically sets the beacon sleep interval to 0 upon initial connection, which is useful for testing purposes.

![Auto-Sleep-Interactive-Example](/Pictures/Auto-Sleep-Interactive-Example.png)

### Auto Sleep After Initial Access

This CNA file automatically configures the beacon's sleep interval upon initial acccess.

## Misc

These CNA files will configure the output format for various default functionalities of Cobalt Strike.

The following table illustrates the CNA files included in the Misc section:

| Name | Description |
|:-----------:|:-----------:|
| [Beacon-Name-Tab.cna](/Misc/Beacon-Name-Tab.cna) | This CNA file modifies the Beacon tab name format from the default to `username`@`hostname` (`pid`) |
| [Beacon-Name-Tab-Colors.cna](/Misc/Beacon-Name-Tab-Colors.cna) | This CNA file modifies the Beacon tab name format from the default to `username`@`hostname` (`pid`), for admin's beacon the color is red, for user's beacon the color is green |
| [CS-All-Tabs-Bold.cna](/Misc/CS-All-Tabs-Bold.cna) | This CNA file makes all CS client tabs bold |
| [CWD-Beacon-Bar.cna](/Misc/CWD-Beacon-Bar.cna) | This CNA file enhances Beacon console status bar to display the Beacon's last known working directory path. Additionally, improves the 'cd' command to support restoring the previous directory path seamlessly (Usage: `cd -`) |

### Beacon Name Tab Example

This CNA file modifies the Beacon tab name format from the default to `username`@`hostname` (`pid`).

![Beacon-Tab-Name-Example](/Pictures/Beacon-Tab-Name-Example.png)

### Beacon Name Tab Colors Example

This CNA file modifies the Beacon tab name format from the default to `username`@`hostname` (`pid`). For an Administrator's Beacon, the tab color is set to red, while for a standard user's Beacon, the tab color is set to green.

![Beacon-Tab-Name-Colors-Example](/Pictures/Beacon-Tab-Name-Colors-Example.png)

### CS All Tabs Bold Example

This CNA file makes all Cobalt Strike client tabs bold.

![CS-All-Tabs-Bold-Example](/Pictures/CS-All-Tabs-Bold-Example.png)

### CWD Beacon Bar Example

This CNA file enhances Beacon console status bar to display the Beacon's last known working directory path.

![CWD-Beacon-Bar-Example](/Pictures/CWD-Beacon-Bar-Example.png)

Additionally, improves the 'cd' command to support restoring the previous directory path seamlessly (Usage: `cd -`).

![CWD-Beacon-Bar-Example-2](/Pictures/CWD-Beacon-Bar-Example-2.png)

Finally, when you have an Administrator's Beacon, the hostname of the target machine changes from the CNA's default green (used for standard users) to red.

![CWD-Beacon-Bar-Example-Admin](/Pictures/CWD-Beacon-Bar-Example-Admin.png)

### Opsec Example

This CNA file alows and blocks default Cobalt Strike commands to improve the opsec.

## SA

These CNA files are used for Situational Awareness.

The following table illustrates the CNA files included in the SA section:

| Name | Description |
|:-----------:|:-----------:|
| [File-Color.cna](/SA/File-Color.cna) | This CNA file outputs files in a colorful format for file hunting |
| [PS-Color.cna](/SA/PS-Color.cna) | This CNA file outputs proccess in a colorful format for process hunting |

## File Color Example

This CNA file outputs files in a colorful format for file hunting.

- [*] Executable files listed in GREEN  
- [*] System-Related files listed in PURPLE  
- [*] Database files listed in YELLOW  
- [*] Office related files listed in RED  
- [*] Source Code files listed in CYAN
- [*] Media files listed in ORANGE
- [*] Directories listed in BLUE

![File-Color-Example](/Pictures/File-Color-Example.png)

## Process Color Example

This CNA file outputs proccess in a colorful format for process hunting.

- [*] This Beacon PID: YELLOW (<beacon_pid>) 
- [*] Windows Processes: GREEN  
- [*] Security Products: RED  

![Process-Color-Example](/Pictures/Process-Color-Example.png)

## Utils

These CNA files are used for general micro tasks during operations.

The following table illustrates the CNA files included in the Utils section:

| Name | Description |
|:-----------:|:-----------:|
| [Sonata.cna](/Utils/Sonata.cna) | This CNA file is a port of the [Sonata](https://github.com/nickvourd/Sonata) tool. Sonata is a file hash calculator that supports MD5, SHA1, SHA256, and SHA512 algorithms. The CNA port enhances functionality by supporting string hash calculations as well |
| [locate.cna](/Utils/locate.cna) | This CNA functions like the `locate` Linux command. Additionally, it performs case-insensitive keyword searches. This CNA requires a Linux CS client |

### Sonata Examples

Hash calculator for local files and strings.

Usage: `Sonata -f/--file <local_filepath> OR Sonata -s/--string <string>`

#### Sonata File 

![Sonata-Example-1](/Pictures/Sonata-Example-1.png)

#### Sonata String

![Sonata-Example-2](/Pictures/Sonata-Example-2.png)

### Locate Example

This CNA functions like the `locate` Linux command. Additionally, it performs case-insensitive keyword searches. This CNA requires a Linux CS client.

ℹ️ When you insert a new file on the host disk, it is recommended to run the `updatedb` command to update the file database and sync the system with the newly added files.

![locate-example](/Pictures/locate-example.png)

