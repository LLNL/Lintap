/*
Convert from LINTAP RAW data (from merge_raw_tsv.sh) to Wintap RAW.

This script supports:

RAW_PROCESS_CONN_INCR

Depends on the macro dp() existing and having the correct path to data. See rawtostdview.sql

*/ 

create or replace macro int_to_ip(i)
as concat_ws('.',i >> 24,i >> 16 & 255,i >> 8 & 255,i & 255)
;

create or replace macro ip_to_int(ip)
as 
   cast(string_split(ip, '.')[1] as UINTEGER) * (256 * 256 * 256) +
   cast(string_split(ip, '.')[2] as UINTEGER) * (256 * 256      ) +
   cast(string_split(ip, '.')[3] as UINTEGER) * (256            ) +
   cast(string_split(ip, '.')[4] as UINTEGER)
;

-- Data directly from merge_raw_tsv.sh
create or replace table raw_lintap_process_conn_incr 
as
select split(netflow_incr_key, '|') [1] pid,
    split(netflow_incr_key, '|') [2] tid,
    split(netflow_incr_key, '|') [3] process_name,
    split(netflow_incr_key, '|') [4] protocol,
    split(netflow_incr_key, '|') [5] activity_type,
    local_ip: case when split(netflow_incr_key, '|')[6] = '' then null else split(netflow_incr_key, '|') [6] end,
    split(netflow_incr_key, '|') [7] local_port,
    remote_ip: case when split(netflow_incr_key, '|')[8] = '' then null else split(netflow_incr_key, '|') [8] end,
    split(netflow_incr_key, '|') [9] remote_port,
    --- Map syscalls to existing types
  ipevent: 
	  case 
	  	WHEN protocol='tcp' and activity_type='accept' then 'TcpIp/Accept'
	  	WHEN protocol='tcp' and activity_type in ('close','shutdown') then 'TcpIp/Disconnect'
	  	WHEN protocol='tcp' and activity_type='connect' then 'TcpIp/Connect'
	  	-- Catch all as I'm not sure what to do with these
	  	WHEN protocol='tcp' and activity_type in ('fcntl','getsockopt','ioctl') then 'TcpIp/TCPCopy'
	  	WHEN protocol='tcp' and activity_type in ('read','recvfrom','recvmsg') then 'TcpIp/Recv'
	  	WHEN protocol='tcp' and activity_type in ('sendfile','sendmsg','sendto','write','writev') then 'TcpIp/Send'
	  	WHEN protocol='udp' and activity_type='connect' then 'UdpIp/Read'
	  	WHEN protocol='udp' and activity_type in ('ioctl') then 'UdpIp/Read'
	  	WHEN protocol='udp' and activity_type='close' then 'UdpIp/Send'
	  	WHEN protocol='udp' and activity_type in ('read','recvfrom','recvmsg') then 'UdpIp/Write'
	  	WHEN protocol='udp' and activity_type in ('write','sendmsg') then 'UdpIp/Send'
	  end,
    * exclude (netflow_incr_key)
from read_parquet(dp('raw_process_conn_incr/**/*.parquet'))
;

create or replace table raw_process_conn_incr
as
select 
    pidhash: p.pid_hash,
	LocalIpAddr: local_ip,
	LocalIpPrivateGateway: null,
	LocalPort: local_port,
	RemoteIpAddr: remote_ip,
	RemoteIpPrivateGateway: null,
	RemotePort: remote_port,
	Protocol: upper(protocol),
	-- Sort components. Note: this same code is in rawutil.py:get_raw_view
    connid: md5(concat_ws(':',list_sort([localipaddr, cast(localport AS varchar),remoteipaddr,CAST(remoteport AS varchar),upper(protocol)]))),
	IncrType: '1 minute',
	IpEvent,
	MinPacketSize: min(bytes),
	MaxPacketSize: max(bytes),
	PacketSizeSquared: null,
	InitialSeq: null,
	PacketSize: sum(bytes),
	EventCount: sum(count),
	FirstSeenMs: min(first_seen_ns/1e9),
	LastSeenMs: max(last_seen_ns/1e9),
	MessageType: activity_type,
	rpci.Hostname,
	ActivityType: activity_type,
	EventTime: min(first_seen_ns/1e9),
	ReceiveTime: min(first_seen_ns/1e9),
	PID,
	ProcessName: rpci.Process_Name,
	AgentId: null,
	rpci.dayPK,
	hourPK: null
from raw_lintap_process_conn_incr rpci
asof join process p 
   on rpci.hostname=p.hostname
  and rpci.pid=p.os_pid
  and rpci.first_seen >= p.process_started
group by all
;

CREATE OR REPLACE TABLE process_conn_incr
AS
SELECT
    'linux' os_family,
    agentid agent_id,
    hostname,
    pidhash pid_hash,
    processname process_name,
    connid conn_id,
    protocol protocol,
    to_timestamp(
        floor((FirstSeenMs) / 60) * 60) incr_start,
    LocalIpAddr local_ip_addr,
    ip_to_int(localipaddr) local_ip_int,
    localport local_port,
    remoteipaddr remote_ip_addr,
    ip_to_int(remoteipaddr) remote_ip_int,
    remoteport remote_port,
    sum(eventcount) total_events,
    sum(packetsize) total_size,
    count(*) num_raw_rows,
    sum(CASE
        WHEN ipevent = 'TcpIp/Accept' THEN eventcount
    END) tcp_accept_count,
    sum(CASE
        WHEN ipevent = 'TcpIp/Connect' THEN eventcount
    END) tcp_connect_count,
    sum(CASE
        WHEN ipevent = 'TcpIp/Disconnect' THEN eventcount
    END) tcp_disconnect_count,
    sum(CASE
        WHEN ipevent = 'TcpIp/Reconnect' THEN eventcount
    END) tcp_reconnect_count,
    sum(CASE
        WHEN ipevent = 'TcpIp/Recv' THEN eventcount
    END) tcp_recv_count,
    sum(CASE
        WHEN ipevent = 'TcpIp/Recv' THEN packetsize
    END) tcp_recv_size,
    sum(CASE
        WHEN ipevent = 'TcpIp/Retransmit' THEN eventcount
    END) tcp_retransmit_count,
    sum(CASE
        WHEN ipevent = 'TcpIp/Send' THEN eventcount
    END) tcp_send_count,
    sum(CASE
        WHEN ipevent = 'TcpIp/Send' THEN packetsize
    END) tcp_send_size,
    sum(CASE
        WHEN ipevent = 'TcpIp/TCPCopy' THEN eventcount
    END) tcp_tcpcopy_count,
    sum(CASE
        WHEN ipevent = 'TcpIp/TCPCopy' THEN packetsize
    END) tcp_tcpcopy_size,
    sum(CASE
        WHEN ipevent = 'UdpIp/Recv' THEN eventcount
    END) udp_recv_count,
    sum(CASE
        WHEN ipevent = 'UdpIp/Recv' THEN packetsize
    END) udp_recv_size,
    sum(CASE
        WHEN ipevent = 'UdpIp/Send' THEN eventcount
    END) udp_send_count,
    sum(CASE
        WHEN ipevent = 'UdpIp/Send' THEN packetsize
    END) udp_send_size, -- Gather some basic stats on traffic
    -- Total events/sizes. In practice, at this level of detail, these *should* be really close the TCP/UDP stats, but exceptions like many connects/disconnects, retransmits, could throw some off.
    min(eventcount) min_10sec_eventcount,
    -- These might need to be fixed. Clarify...
    max(eventcount) max_10sec_eventcount,
    min(minpacketsize) min_size,
    max(maxpacketsize) max_size,
    -- TCP Stats - only doing send/receive for now.
    sum(packetsizesquared) sq_size,
    max(CASE
        WHEN ipevent = 'TcpIp/Recv' THEN eventcount
    END) max_tcp_recv_count,
    min(CASE
        WHEN ipevent = 'TcpIp/Recv' THEN minpacketsize
    END) min_tcp_recv_size,
    max(CASE
        WHEN ipevent = 'TcpIp/Recv' THEN maxpacketsize
    END) max_tcp_recv_size,
    sum(CASE
        WHEN ipevent = 'TcpIp/Recv' THEN packetsizesquared
    END) sq_tcp_recv_size, --
    max(CASE
        WHEN ipevent = 'TcpIp/Send' THEN eventcount
    END) max_tcp_send_count,
    min(CASE
        WHEN ipevent = 'TcpIp/Send' THEN minpacketsize
    END) min_tcp_send_size,
    max(CASE
        WHEN ipevent = 'TcpIp/Send' THEN maxpacketsize
    END) max_tcp_send_size,
    sum(CASE
        WHEN ipevent = 'TcpIp/Send' THEN packetsizesquared
    END) sq_tcp_send_size, -- UDP Stats
    max(CASE
        WHEN ipevent = 'UdpIp/Recv' THEN eventcount
    END) max_udp_recv_count,
    min(CASE
        WHEN ipevent = 'UdpIp/Recv' THEN minpacketsize
    END) min_udp_recv_size,
    max(CASE
        WHEN ipevent = 'UdpIp/Recv' THEN maxpacketsize
    END) max_udp_recv_size,
    sum(CASE
        WHEN ipevent = 'UdpIp/Recv' THEN packetsizesquared
    END) sq_udp_recv_size, --
    max(CASE
        WHEN ipevent = 'UdpIp/Send' THEN eventcount
    END) max_udp_send_count,
    min(CASE
        WHEN ipevent = 'UdpIp/Send' THEN minpacketsize
    END) min_udp_send_size,
    max(CASE
        WHEN ipevent = 'UdpIp/Send' THEN maxpacketsize
    END) max_udp_send_size,
    sum(CASE
        WHEN ipevent = 'UdpIp/Send' THEN packetsizesquared
    END) sq_udp_send_size,
    to_timestamp(min((firstseenms))) first_seen,
    to_timestamp(max((lastseenms))) last_seen
FROM raw_process_conn_incr
GROUP BY ALL
;

CREATE OR REPLACE TABLE process_net_conn
AS
SELECT
    os_family,
    agent_id,
    hostname,
    pid_hash,
    process_name,
    conn_id,
    protocol,
    local_ip_addr,
    local_port,
    remote_ip_addr,
    remote_port,
    sum(total_events) total_events,
    sum(total_size) total_size,
    sum(sq_size) sq_size,
    sum(num_raw_rows) num_raw_rows,
    sum(tcp_accept_count) tcp_accept_count,
    sum(tcp_connect_count) tcp_connect_count,
    sum(tcp_disconnect_count) tcp_disconnect_count,
    sum(tcp_reconnect_count) tcp_reconnect_count,
    sum(tcp_recv_count) tcp_recv_count,
    sum(tcp_recv_size) tcp_recv_size,
    sum(sq_tcp_recv_size) sq_tcp_recv_size,
    sum(tcp_retransmit_count) tcp_retransmit_count,
    sum(tcp_send_count) tcp_send_count,
    sum(tcp_send_size) tcp_send_size,
    sum(sq_tcp_send_size) sq_tcp_send_size,
    sum(tcp_tcpcopy_count) tcp_tcpcopy_count,
    sum(tcp_tcpcopy_size) tcp_tcpcopy_size,
    sum(udp_recv_count) udp_recv_count,
    sum(udp_recv_size) udp_recv_size,
    sum(sq_udp_recv_size) sq_udp_recv_size,
    sum(udp_send_count) udp_send_count,
    sum(udp_send_size) udp_send_size,
    sum(sq_udp_send_size) sq_udp_send_size,
    min(first_seen) first_seen,
    max(last_seen) last_seen
FROM process_conn_incr
GROUP BY ALL
;
