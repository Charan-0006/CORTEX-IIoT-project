# Context Attribute Repository Mapping - CORTEX

This document defines the semantic mapping of raw telemetry features in TON-IoT into the six primary Context Dimensions of the CORTEX Contextual Intelligence Engine.

---

## The 6 Context Dimensions

To provide structured, explainable threat intelligence, CORTEX organizes raw telemetry into six logical dimensions:

1. **Temporal Context**: Timeline occurrences, duration, and operational cadence.
2. **Asset Context**: Identifies and structures the targets/actors involved (IPs, Ports, PIDs, processes, device identifiers).
3. **Network Context**: Commmunications protocols, packet stats, and packet/volume metrics.
4. **Device Context**: Physical IoT sensor readings (temperature, location) and actuator states (relay switches, registers).
5. **Operational Context**: Host OS performance metrics (CPU cycles, RAM footprint growth, Page faults, Disk I/O).
6. **Security Context**: Flags alerts, category types, and protocol anomalies.

---

## Context Mapping Registry Table

| Context Dimension | Raw Feature | Standard Attribute | Source Telemetry | DataType | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Temporal Context** | `ts` | `timestamp` | Network, Linux, Windows | Float | Epoch timestamp of telemetry event. |
| | `date` + `time` | `timestamp` | IoT (All) | Float | Unified UTC epoch timestamp. |
| | `duration` | `session_duration` | Network | Float | Connection duration in seconds. |
| | `Process_Elapsed_Time` | `process_elapsed_time` | Windows | Float | Process running time in seconds. |
| **Asset Context** | `src_ip` | `source_ip` | Network | String | Source IP address. |
| | `dst_ip` | `dest_ip` | Network | String | Destination IP address. |
| | `src_port` | `source_port` | Network | Integer | Source connection port. |
| | `dst_port` | `dest_port` | Network | Integer | Destination connection port. |
| | `PID` | `process_id` | Linux, Windows | Integer | OS Kernel Process Identifier. |
| | `CMD` | `process_name` | Linux | String | Binary/Command execution name. |
| | (Source dataset name) | `device_id` | IoT (All) | String | Standard device class identification. |
| **Network Context** | `proto` | `network_protocol` | Network | String | Transport layer protocol. |
| | `service` | `app_service` | Network | String | Dynamically identified application service. |
| | `src_bytes` | `bytes_sent` | Network | Integer | Payload bytes sent by source. |
| | `dst_bytes` | `bytes_received` | Network | Integer | Payload bytes returned by destination. |
| | `conn_state` | `connection_state` | Network | String | Zeek state flags (SF, S0, REJ, OTH). |
| | `src_pkts` | `packets_sent` | Network | Integer | Count of packets sent from source. |
| | `dst_pkts` | `packets_received` | Network | Integer | Count of packets sent from destination. |
| | `src_ip_bytes` | `ip_bytes_sent` | Network | Integer | Total IP header bytes sent from source. |
| | `dst_ip_bytes` | `ip_bytes_received` | Network | Integer | Total IP header bytes returned. |
| **Device Context** | `fridge_temperature` | `device_temperature` | Fridge | Float | Fridge internal sensor temp (°C). |
| | `temp_condition` | `status_condition` | Fridge | String | Category: high, normal, low. |
| | `door_state` | `actuator_state` | Garage Door | String | Actuator state: open, closed. |
| | `sphone_signal` | `signal_active` | Garage Door | Boolean | Mobile control signal status. |
| | `latitude` | `geo_latitude` | GPS Tracker | Float | GPS latitude coordinate. |
| | `longitude` | `geo_longitude` | GPS Tracker | Float | GPS longitude coordinate. |
| | `FC1_Read_Input_Register`| `modbus_reg_fc1` | Modbus | Integer | Modbus function code 1 register. |
| | `FC2_Read_Discrete_Value`| `modbus_reg_fc2` | Modbus | Integer | Modbus function code 2 register. |
| | `FC3_Read_Holding_Register`| `modbus_reg_fc3` | Modbus | Integer | Modbus function code 3 register. |
| | `FC4_Read_Coil` | `modbus_reg_fc4` | Modbus | Integer | Modbus function code 4 register. |
| | `motion_status` | `sensor_binary_status` | Motion Light | Integer | Motion sensor indicator (0 or 1). |
| | `light_status` | `actuator_state` | Motion Light | String | Smart light bulb status (on, off). |
| | `current_temperature` | `ambient_temperature` | Thermostat | Float | Ambient environment temperature. |
| | `thermostat_status` | `actuator_binary_status`| Thermostat | Integer | Thermostat trigger status (0 or 1). |
| | `temperature` | `weather_temp` | Weather | Float | Temperature sensor metric. |
| | `pressure` | `weather_pressure` | Weather | Float | Pressure sensor metric. |
| | `humidity` | `weather_humidity` | Weather | Float | Relative humidity percentage. |
| **Operational Context**| `CPU` | `cpu_usage_pct` | Linux, Windows | Float | Process CPU utilization percentage. |
| | `MEM` | `memory_usage_pct` | Linux | Float | Process RAM consumption percentage. |
| | `VSIZE` | `virtual_mem_mb` | Linux | Float | Process total virtual memory footprint. |
| | `RSIZE` | `resident_mem_mb` | Linux | Float | Process resident physical RAM (MB). |
| | `VGROW` | `virtual_mem_growth_mb` | Linux | Float | Virtual memory growth increment. |
| | `RGROW` | `resident_mem_growth_mb`| Linux | Float | Resident memory growth increment. |
| | `RDDSK` | `disk_read_kb_s` | Linux | Float | Process disk read speed (KB/s). |
| | `WRDSK` | `disk_write_kb_s` | Linux | Float | Process disk write speed (KB/s). |
| | `State` | `thread_state` | Linux | String | Process scheduling state (R, S, D, Z). |
| | `Memory_Available_Bytes` | `memory_available_bytes`| Windows | Integer | Available unallocated RAM. |
| | `Process_Working_Set_ Private`| `process_memory_bytes` | Windows | Integer | Physical RAM pages reserved by process. |
| | `LogicalDisk(_Total) Disk Read Bytes sec` | `disk_read_bytes_s` | Windows | Float | Windows logical partition read speed. |
| | `LogicalDisk(_Total) Disk Write Bytes sec`| `disk_write_bytes_s`| Windows | Float | Windows logical partition write speed. |
| **Security Context** | `label` | `security_alert_label` | All | Integer | Alert flag (0=normal, 1=attack). |
| | `type` | `attack_class` | All | String | Category type (DoS, backdoor, normal). |
| | `weird_name` | `protocol_anomaly_name` | Network | String | Zeek-reported protocol violation name. |
| | `weird_notice` | `anomaly_notice_triggered`| Network | Boolean | Protocol anomaly trigger alert flag. |
| | `dns_rejected` | `dns_query_rejected` | Network | Boolean | Rejected status of DNS queries. |
