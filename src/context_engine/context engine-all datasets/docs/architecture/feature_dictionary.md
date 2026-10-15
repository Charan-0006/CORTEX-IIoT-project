# TON-IoT Feature Dictionary - CORTEX

This Feature Dictionary acts as a complete registry of telemetry features available in the processed TON-IoT datasets, detailing their names, datatypes, origin sources, and descriptions.

---

## 1. Network Telemetry Features
*Source: `Processed_Network_dataset/Network_dataset_*.csv`*

### Connection Activity Profile
| Feature | Type | Description |
| :--- | :--- | :--- |
| `ts` | Integer (Epoch) | Timestamp representing the start of the network flow connection. |
| `src_ip` | String | Source IP address originating the endpoint connection. |
| `src_port` | Integer | Source TCP/UDP port originating the connection. |
| `dst_ip` | String | Destination IP address responding to the connection. |
| `dst_port` | Integer | Destination TCP/UDP port responding to the connection. |
| `proto` | String | Transport layer protocol of the flow connection (e.g., `tcp`, `udp`, `icmp`). |
| `service` | String | Dynamically detected application protocol (e.g., `dns`, `http`, `ssl`, or `-` if none). |
| `duration` | Float | Connection duration in seconds (computed as time of last packet minus time of first packet). |
| `src_bytes` | Integer | Payload bytes sent from the source to destination. |
| `dst_bytes` | Integer | Payload bytes sent from the destination to source. |
| `conn_state` | String | Zeek connection state flags (e.g., `S0`, `S1`, `SF`, `REJ`, `OTH`). |
| `missed_bytes` | Integer | Number of missing bytes in content gaps (unacknowledged TCP segments). |

### Statistical Activity Profile
| Feature | Type | Description |
| :--- | :--- | :--- |
| `src_pkts` | Integer | Count of packets transmitted from the source host. |
| `src_ip_bytes` | Integer | Count of IP header bytes transmitted from the source host (includes IP headers). |
| `dst_pkts` | Integer | Count of packets transmitted from the destination host. |
| `dst_ip_bytes` | Integer | Count of IP header bytes transmitted from the destination host. |

### DNS Activity Profile
| Feature | Type | Description |
| :--- | :--- | :--- |
| `dns_query` | String | Domain name queried in the DNS request. |
| `dns_qclass` | Integer | DNS query class value (typically `1` for Internet). |
| `dns_qtype` | Integer | DNS resource record type (e.g., `1` for A, `28` for AAAA, `12` for PTR). |
| `dns_rcode` | Integer | DNS response code returned by the server (e.g., `0` for No Error, `3` for NXDomain). |
| `dns_AA` | Boolean/Char | Authoritative Answer flag; `T` if the responding server is authoritative. |
| `dns_RD` | Boolean/Char | Recursion Desired flag; `T` if recursion was requested by client. |
| `dns_RA` | Boolean/Char | Recursion Available flag; `T` if server supports recursion. |
| `dns_rejected` | Boolean/Char | DNS rejection flag; `T` if the query was rejected by the server. |

### SSL Activity Profile
| Feature | Type | Description |
| :--- | :--- | :--- |
| `ssl_version` | String | TLS/SSL protocol version chosen by the server (e.g., `TLSv12`, `TLSv13`). |
| `ssl_cipher` | String | Cipher suite agreed upon for connection security. |
| `ssl_resumed` | Boolean/Char | Indicates if the SSL session was resumed from a previous handshake (`T`/`F`). |
| `ssl_established` | Boolean/Char | `T` if the SSL handshake successfully completed and session established. |
| `ssl_subject` | String | Common Name/Subject of the X.509 certificate presented by the server. |
| `ssl_issuer` | String | Issuer Name (Certificate Authority) of the certificate. |

### HTTP Activity Profile
| Feature | Type | Description |
| :--- | :--- | :--- |
| `http_trans_depth` | Integer/Char | Depth of pipeline transaction on this single connection. |
| `http_method` | String | Request verb (e.g., `GET`, `POST`, `HEAD`, `PUT`). |
| `http_uri` | String | Target URI path queried in the HTTP request. |
| `http_referrer` | String | Referer header field showing source webpage of request. |
| `http_version` | String | Version of the HTTP protocol utilized (e.g., `1.1`, `1.0`). |
| `http_request_body_len`| Integer | Uncompressed payload size in bytes sent by the client. |
| `http_response_body_len`| Integer | Uncompressed payload size in bytes returned by the server. |
| `http_status_code` | Integer | HTTP response status code (e.g., `200`, `404`, `500`). |
| `http_user_agent` | String | Client's user-agent string identifier. |
| `http_orig_mime_types` | String | Mime-type header sent by the client (origin). |
| `http_resp_mime_types` | String | Mime-type header returned by the server (response). |

### Protocol Violation & Labelling
| Feature | Type | Description |
| :--- | :--- | :--- |
| `weird_name` | String | Name of protocol violation or parsing anomaly caught by Zeek (e.g., `bad_TCP_checksum`). |
| `weird_addl` | String | Additional context/payload snippets associated with the violation. |
| `weird_notice` | Boolean/Char | `T`/`F` indicating whether this anomaly triggered a higher security notice. |
| `label` | Integer | Security category label: `0` (Normal), `1` (Attack). |
| `type` | String | Sub-category of traffic: `normal`, `dos`, `ddos`, `backdoor`, `injection`, `bruteforce`, `password`, `scanning`, `xss`, `mitm`. |

---

## 2. IoT Telemetry Features
*Source: `Processed_IoT_dataset/IoT_*.csv`*

All IoT datasets share standard framing columns (`date`, `time`, `label`, `type`) along with device-specific telemetry:

### Core Common IoT Fields
- `date` (String): Date of logging (e.g., `31-Mar-19`).
- `time` (String): Time of logging (e.g., `12:36:52`, often has leading/trailing whitespaces).
- `label` (Integer): `0` for normal, `1` for attack.
- `type` (String): Attack sub-category or `normal`.

### Device-Specific Fields
- **Fridge** (`IoT_Fridge.csv`):
  - `fridge_temperature` (Float): Core sensor reading of fridge temperature.
  - `temp_condition` (String): Temperature evaluation string (e.g., `normal`, `high`, `low`).
- **Garage Door** (`IoT_Garage_Door.csv`):
  - `door_state` (String): State of the door actuator (e.g., `open`, `closed`).
  - `sphone_signal` (String): Indicates mobile signal connection state (e.g., `true`, `false`).
- **GPS Tracker** (`IoT_GPS_Tracker.csv`):
  - `latitude` (Integer/Float): Latitude coordinate of the tracking unit.
  - `longitude` (Integer/Float): Longitude coordinate of the tracking unit.
- **Modbus PLC** (`IoT_Modbus.csv`):
  - `FC1_Read_Input_Register` (Integer): Modbus function code 1 telemetry (binary register state).
  - `FC2_Read_Discrete_Value` (Integer): Modbus function code 2 discrete input status.
  - `FC3_Read_Holding_Register` (Integer): Modbus function code 3 analog output value.
  - `FC4_Read_Coil` (Integer): Modbus function code 4 coil register value.
- **Motion Light** (`IoT_Motion_Light.csv`):
  - `motion_status` (Integer): Binary sensor value (`1` = Motion detected, `0` = Quiet).
  - `light_status` (String): Light bulb status indicator (`on`, `off`).
- **Thermostat** (`IoT_Thermostat.csv`):
  - `current_temperature` (Integer/Float): Current ambient temperature measured by the device.
  - `thermostat_status` (Integer/Boolean): Actuator state (`1` = Active heating/cooling, `0` = Idle).
- **Weather Station** (`IoT_Weather.csv`):
  - `temperature` (Float): Ambient atmospheric temperature.
  - `pressure` (Float): Atmospheric pressure.
  - `humidity` (Float): Relative humidity percentage.

---

## 3. Linux Host OS Telemetry Features
*Source: `Processed_Linux_dataset/linux_*.csv`*

### Linux Disk Activity (`linux_disk_*.csv`)
| Feature | Type | Description |
| :--- | :--- | :--- |
| `ts` | Integer | Unix epoch timestamp of disk measurement. |
| `PID` | Integer | Process identifier active in the kernel. |
| `RDDSK` | Float/Integer | Rate of disk read operations (KB/s). |
| `WRDSK` | Float/Integer | Rate of disk write operations (KB/s). |
| `WCANCL` | Float/Integer | Canceled disk write bytes (withdrawn writes). |
| `DSK` | Float/Integer | Disk utilization percentage. |
| `CMD` | String | Name of the process interacting with the disk. |

### Linux Memory Activity (`linux_memory*.csv`)
| Feature | Type | Description |
| :--- | :--- | :--- |
| `ts` | Integer | Unix epoch timestamp. |
| `PID` | Integer | Process identifier. |
| `MINFLT` | Integer | Minor page faults (resolved in RAM). |
| `MAJFLT` | Integer | Major page faults (requires disk swap lookup). |
| `VSTEXT` | Integer | Virtual memory size used by process shared text segment (KB). |
| `VSIZE` | Float | Total virtual memory footprint (MB). |
| `RSIZE` | Float/Integer | Resident set size (physical RAM allocation, MB). |
| `VGROW` | Float/Integer | Growth in virtual memory size during last interval. |
| `RGROW` | Float/Integer | Growth in resident memory size during last interval. |
| `MEM` | Float/Integer | Memory utilization percentage. |
| `CMD` | String | Process name. |

### Linux Process Scheduling Activity (`Linux_process_*.csv`)
| Feature | Type | Description |
| :--- | :--- | :--- |
| `ts` | Integer | Unix epoch timestamp. |
| `PID` | Integer | Process identifier. |
| `TRUN` | Integer | Count of threads in state RUNNING (R). |
| `TSLPI` | Integer | Count of threads in state INTERRUPTIBLE SLEEP (S). |
| `TSLPU` | Integer | Count of threads in state UNINTERRUPTIBLE SLEEP (D). |
| `POLI` | String | Scheduling policy (e.g., `norm` for timesharing, `rr` / `fifo` for realtime). |
| `NICE` | Integer | Nice value (-20 highest priority, +19 lowest priority). |
| `PRI` | Integer | Thread scheduling priority (0 highest, 139 lowest). Real-time uses 0-99. |
| `RTPR` | Integer | Realtime priority (POSIX standard). |
| `CPUNR` | Integer | Logical CPU core identifier executing the main process thread. |
| `Status` | String | Process lifecycle status (e.g., `N` for new process in this interval). |
| `EXC` | Integer | Process exit code or termination signal. |
| `State` | String | Thread execution state: `R` (running), `S` (sleeping), `D` (uninterruptible sleep), `Z` (zombie), `T` (stopped). |
| `CPU` | Float/Integer | CPU core utilization percentage. |
| `CMD` | String | Name of the process command. |

---

## 4. Windows Host OS Telemetry Features
*Source: `Processed_Windows_dataset/windows*.csv`*

The Windows telemetry contains a rich set of 127 to 135 features covering CPU performance, process threads, memory cache, TCP parameters, and logical disk statistics. Key feature categories:

### Windows CPU/Processor Counters
- `Processor_pct_ Idle_Time` / `Processor_pct_ Processor_Time`: Proportions of CPU cycle budget spent idling vs. executing tasks.
- `Processor_DPCs_Queued_sec` / `Processor_pct_ DPC_Time`: Deferred Procedure Calls (DPCs) queued per second. Spikes are indicative of driver errors or flood conditions.
- `Processor_Interrupts_sec`: Frequency of hardware/software interrupts.
- `Processor_pct_ User_Time` / `Processor_pct_ Privileged_Time`: User mode execution vs. Kernel mode execution times.

### Windows Process Performance
- `Process_Working_Set_Private` / `Process_Working_Set_Peak`: Memory pages physically mapped in RAM for the processes.
- `Process_Virtual_Bytes`: Total allocated virtual memory address space.
- `Process_Thread_Count`: Count of active execution threads.
- `Process_IO_Read_Operations_sec` / `Process_IO_Write_Operations_sec`: Disk/device file I/O operations rate.

### Windows Memory Manager
- `Memory_Available_Bytes`: Volume of physical memory immediately allocatable.
- `Memory_Committed_Bytes`: Volume of virtual memory committed to the paging file.
- `Memory_Page_Faults_sec` / `Memory_Pages_Input_sec`: Page fault resolutions requiring disk load.

### Windows Logical Disk Performance
- `LogicalDisk_pct_Idle_Time` / `LogicalDisk_pct_Disk_Time`: Percentage of time the disk was busy servicing requests.
- `LogicalDisk_Disk_Read_Bytes_sec` / `LogicalDisk_Disk_Write_Bytes_sec`: Throughput rate for disk I/O.
- `LogicalDisk_Avg_Disk_sec_Transfer`: Average latency in seconds to complete an I/O operation.
