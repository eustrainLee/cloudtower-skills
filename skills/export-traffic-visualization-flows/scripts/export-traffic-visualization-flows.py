# -*- coding: utf-8 -*-
import argparse
import base64
import datetime
import json
import os
import re
import socket
import ssl
import sys
import time

if sys.version_info.major == 2:
    import httplib

    # Python 2.7: Custom HTTPSConnection that skips SSL certificate verification
    class HTTPSConnection(httplib.HTTPSConnection):
        def connect(self):
            timeout = getattr(self, 'timeout', None)
            sock = socket.create_connection((self.host, self.port), timeout)
            if self._tunnel_host:
                self.sock = sock
                self._tunnel()
            # Disable SSL certificate verification
            self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file,
                                        cert_reqs=ssl.CERT_NONE)
else:
    import http.client as httplib

DEBUG = False

try:
    _basestring = basestring  # Python 2
except NameError:
    _basestring = str  # Python 3


def _ip_literal_key(addr):
    """
    Return ('v4', bytes) or ('v6', bytes) if addr is a valid IPv4/IPv6 literal, else None.
    Uses inet_pton so different textual forms of the same address compare equal.
    """
    if addr is None or not isinstance(addr, _basestring):
        return None
    addr = addr.strip()
    if not addr:
        return None
    try:
        return ("v4", socket.inet_pton(socket.AF_INET, addr))
    except (socket.error, OSError, ValueError):
        pass
    try:
        return ("v6", socket.inet_pton(socket.AF_INET6, addr))
    except (socket.error, OSError, ValueError):
        return None


def _is_ip_literal(addr):
    return _ip_literal_key(addr) is not None


def _ip_addrs_equal(a, b):
    """True if a and b are the same IPv4/IPv6 address (any literal spelling) or equal strings."""
    if a is None or b is None:
        return False
    a = a.strip()
    b = b.strip()
    ka = _ip_literal_key(a)
    kb = _ip_literal_key(b)
    if ka is not None and kb is not None:
        return ka == kb
    return a == b


class ObsRef(object):
    """Single observability selector: raw token from --obs (name, id, or IPv4/IPv6)."""

    __slots__ = ("raw", "is_ip")

    def __init__(self, raw):
        self.raw = raw.strip()
        self.is_ip = _is_ip_literal(self.raw)


def parse_single_obs_arg(s):
    """
    Parse --obs: at most one value; comma-separated lists are rejected.
    Returns None if unset or empty.
    """
    if s is None:
        return None
    s = s.strip()
    if not s:
        return None
    if "," in s:
        print("error: --obs accepts only one value (comma-separated list is not allowed)")
        exit(1)
    return ObsRef(s)


_RFC3339_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})?$"
)


def parse_rfc3339_timestamp(s):
    """
    Parse an RFC3339 / ISO8601 timestamp into naive UTC datetime.
    If timezone is omitted, the value is treated as UTC.
    """
    from decimal import Decimal, InvalidOperation

    s = s.strip()
    if not s:
        raise ValueError("empty timestamp")
    m = _RFC3339_RE.match(s)
    if not m:
        raise ValueError("not a valid RFC3339 timestamp")
    y, mo, d, h, mi, sec, frac, tz = m.group(1, 2, 3, 4, 5, 6, 7, 8)
    y, mo, d, h, mi, sec = int(y), int(mo), int(d), int(h), int(mi), int(sec)
    if frac:
        try:
            us = int(Decimal("0." + frac) * Decimal(1000000))
            if us > 999999:
                us = 999999
        except (InvalidOperation, ValueError):
            raise ValueError("invalid fractional seconds")
    else:
        us = 0
    try:
        dt = datetime.datetime(y, mo, d, h, mi, sec, us)
    except ValueError as e:
        raise ValueError("invalid date or time: {}".format(e))
    if tz is None:
        return dt
    if tz.upper() == "Z":
        return dt
    if len(tz) != 6 or tz[0] not in "+-" or tz[3] != ":":
        raise ValueError("invalid timezone offset")
    sign = 1 if tz[0] == "+" else -1
    oh = int(tz[1:3])
    om = int(tz[4:6])
    delta = datetime.timedelta(hours=sign * oh, minutes=sign * om)
    return dt - delta


def instance_mgmt_ip(inst):
    vs = inst.get("vm_spec")
    if not vs:
        return None
    ip = vs.get("ip")
    if ip is None:
        return None
    ip = ip.strip()
    return ip if ip else None


def select_observability_instances(instances, obs_ref):
    """obs_ref None -> all instances. Else match by name, id, or vm_spec.ip."""
    if obs_ref is None:
        return list(instances)
    picked = []
    if obs_ref.is_ip:
        for inst in instances:
            if _ip_addrs_equal(obs_ref.raw, instance_mgmt_ip(inst)):
                picked.append(inst)
                break
        if not picked:
            print(
                "error: no observability instance with vm_spec.ip matching {}".format(
                    obs_ref.raw
                )
            )
            exit(1)
    else:
        for inst in instances:
            if inst.get("name") == obs_ref.raw or inst.get("id") == obs_ref.raw:
                picked.append(inst)
                break
        if not picked:
            print(
                "error: no observability instance with name or id {}".format(
                    obs_ref.raw
                )
            )
            exit(1)
    return picked


def dedupe_ip_pairs(pairs):
    seen = set()
    out = []
    for ip, label in pairs:
        if ip not in seen:
            seen.add(ip)
            out.append((ip, label))
    return out


def resolve_proxy_target_ips(obs_ref, instances):
    """List of (ip, label) for Tower /api/ovm/{ip}/ proxy. Deduped by IP."""
    if obs_ref is None:
        pairs = []
        for inst in instances:
            mgmt = instance_mgmt_ip(inst)
            if mgmt:
                pairs.append((mgmt, inst.get("name") or inst.get("id")))
        return dedupe_ip_pairs(pairs)
    if obs_ref.is_ip:
        return [(obs_ref.raw, obs_ref.raw)]
    sel = select_observability_instances(instances, obs_ref)
    inst = sel[0]
    mgmt = instance_mgmt_ip(inst)
    if not mgmt:
        print(
            "error: vm_spec.ip missing for observability instance {}".format(obs_ref.raw)
        )
        exit(1)
    return [(mgmt, inst.get("name") or obs_ref.raw)]


def resolve_proxy_admin_target_ip(obs_ref, instances):
    """Exactly one IP for list-requests / request-status / download / delete."""
    if obs_ref is None:
        print(
            "error: --list-requests / --request-status / --download-task / --delete-request require --obs with one target"
        )
        exit(1)
    pairs = resolve_proxy_target_ips(obs_ref, instances)
    if len(pairs) != 1:
        print("error: proxy admin operations need exactly one resolved management IP")
        exit(1)
    return pairs[0][0]


TOWERURL = None
TOKEN = None
USERNAME = ''
PASSWORD = ''
LOGIN_TYPE = 'LOCAL'

def load_env_file(env_file_path):
    """
    Load environment variables from a .env file
    Supports KEY=value format, with optional quotes and comments
    """
    env_vars = {}
    if not os.path.exists(env_file_path):
        raise IOError("Environment file not found: {}".format(env_file_path))
    
    with open(env_file_path, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            # Parse KEY=value format
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                # Remove quotes if present
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]
                env_vars[key] = value
    
    # Set environment variables
    for key, value in env_vars.items():
        os.environ[key] = value

def init_env_vars():
    """
    Initialize environment variables from system environment or .env file
    """
    global TOWERURL, TOKEN, USERNAME, PASSWORD, LOGIN_TYPE
    
    TOWERURL = os.environ.get("TOWER_URL")
    if TOWERURL is None:
        raise ValueError("TOWER_URL environment variable is required")
    TOWERURL = TOWERURL.rstrip("/")
    
    TOKEN = os.getenv("TOWER_TOKEN") or ""
    if TOKEN is None or TOKEN == "":
        USERNAME = os.environ.get("TOWER_USERNAME")
        PASSWORD = os.environ.get("TOWER_PASSWORD")
        if USERNAME is None or PASSWORD is None:
            raise ValueError("TOWER_USERNAME and TOWER_PASSWORD environment variables are required when TOWER_TOKEN is not set")
        LOGIN_TYPE = os.getenv("TOWER_LOGIN_TYPE") or "LOCAL"

def request(url, path, method, body, headers):
    if url[0:5] == "https":
        if sys.version_info.major == 2:
            # Python 2.7: Use custom HTTPSConnection that skips SSL verification
            connection = HTTPSConnection(url[8:])
        else:
            # Python 3: use ssl context for unverified connections
            connection = httplib.HTTPSConnection(url[8:], context=ssl._create_unverified_context())
    else:
        connection = httplib.HTTPConnection(url[7:])
    if "/api/admin" in path:
        credentials = "admin:cloudtower"
        if sys.version_info.major == 2:
            # Python 2.7: b64encode accepts and returns string
            encoded_credentials = base64.b64encode(credentials)
        else:
            # Python 3: b64encode requires bytes and returns bytes
            encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        headers['Authorization'] = 'Basic {}'.format(encoded_credentials)

    connection.request(method, path, body, headers)
    return connection.getresponse()


def graphqlRequest(url, query, query_name, variables):
    body = json.dumps({"operationName": None, "query": query, "variables": variables})
    header = {
        "Content-Length": len(body),
        "Content-Type": "application/json",
        "Authorization": TOKEN,
    }
    resp_text = request(url, "/api", "POST", body, header).read()
    # Python 3 returns bytes, Python 2 returns string
    if sys.version_info.major == 3 and isinstance(resp_text, bytes):
        resp_text = resp_text.decode('utf-8')
    try:
        resp = json.loads(resp_text)
    except Exception:
        # If resp_text is not JSON, raise an informative error
        raise Exception("Non-JSON response from GraphQL endpoint: %s" % str(resp_text))

    # If request succeeded, GraphQL returns "data"
    if resp.get("data") is not None:
        return resp["data"].get(query_name)
    # GraphQL standard uses "errors" (list)
    if resp.get("errors"):
        # collect messages from errors
        try:
            msgs = []
            for e in resp["errors"]:
                if isinstance(e, dict) and "message" in e:
                    msgs.append(e["message"])
                else:
                    msgs.append(str(e))
            raise Exception("GraphQL errors: %s" % "; ".join(msgs))
        except Exception:
            raise
    # Some APIs may use "error" single field
    if resp.get("error") is not None:
        raise Exception("GraphQL error: %s" % str(resp.get("error")))
    # Fallback: unknown response shape
    raise Exception("Unknown GraphQL response: %s" % json.dumps(resp))

def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="debug mode, print more logs", action="store_true", required=False)
    parser.add_argument("--env", help="path to environment file (.env) to load environment variables from", type=str, required=False)

    parser.add_argument(
        "--obs",
        help="Single observability instance name, id, or management IPv4/IPv6 (vm_spec.ip). Omit for all instances. Only one value; no comma-separated list.",
        type=str,
        required=False,
    )
    parser.add_argument(
        "--from_time",
        help="Start time (RFC3339), e.g. 2025-12-22T00:00:00Z or 2025-12-22T08:00:00+08:00. "
        "If omitted, defaults to {to_time} - 1 day.",
        type=str,
        required=False,
    )
    parser.add_argument(
        "--to_time",
        help="End time (RFC3339), e.g. 2025-12-22T01:00:00Z. Defaults to now.",
        type=str,
        required=False,
    )
    parser.add_argument("--clusters", help="elf cluster names or ids, splict with comma.", type=str, required=False)
    parser.add_argument("--network_type", help="network type, such as 'VMNetwork', 'SystemNetwork', 'ContainerNetwork'. No limit if the argument is not set.", type=str, required=False)
    parser.add_argument("--filter_low_bandwidth", help="filter low bandwidth, False as default", action="store_true", required=False)
    parser.add_argument("--time_zone", help="time zone default to 'Asia/Shanghai', requires the traffic visualization support it(since 1.4.0).", type=str, required=False)
    parser.add_argument("--file_name", help="file name default to '{filename_prefix}-{from_time}-{to_time}'. conflict with --file_name_prefix", type=str, required=False)
    parser.add_argument("--file_name_prefix", help="file name prefix default to 'export-flows' require --file_name is not provided, conflict with --file_name", type=str, required=False)
    parser.add_argument(
        "--create-tower-task",
        help="create export via Tower GraphQL (UI-visible). If omitted, use HTTPS /api/ovm/{ip}/traffic-visualization/ (background).",
        action="store_true",
        required=False,
    )
    parser.add_argument(
        "--list-requests",
        help="GET /internal/async/requests via Tower proxy (no export run). Requires --obs.",
        action="store_true",
        required=False,
    )
    parser.add_argument(
        "--request-status",
        help="GET /internal/async/request/{id} (request UUID). No export run.",
        type=str,
        required=False,
    )
    parser.add_argument(
        "--download-task",
        help="GET /download/{task_id} and save CSV. Requires --output.",
        type=str,
        required=False,
    )
    parser.add_argument(
        "--output",
        help="Output file path for --download-task or --sync-export.",
        type=str,
        required=False,
    )
    parser.add_argument(
        "--delete-request",
        help="DELETE /internal/async/request/{id} (request UUID). No export run.",
        type=str,
        required=False,
    )
    parser.add_argument(
        "--sync-export",
        help="Tower proxy only: create async export, poll until ready, save CSV to --output, then delete request. Use only for very small result sets.",
        action="store_true",
        required=False,
    )
    parser.add_argument(
        "--sync-poll-interval",
        help="Seconds between status polls for --sync-export (default: 5).",
        type=float,
        default=5.0,
        required=False,
    )
    parser.add_argument(
        "--sync-timeout",
        help="Max seconds to wait for export ready for --sync-export (default: 600).",
        type=int,
        default=600,
        required=False,
    )
    return parser

def get_elf_clusters():
    """
    get_elf_clusters returns the elf clusters
    """
    return graphqlRequest(TOWERURL,
                          """
                          query clusters {
                            clusters {
                              id
                              name
                            }
                          }
                          """,
                          "clusters",
                          {})

def get_elf_clusters_by_names_or_ids(names_or_ids):
    """
    get_elf_cluster_ids_by_names_or_ids returns the elf cluster ids by names or ids
    """
    clusters = get_elf_clusters()
    if names_or_ids is None or len(names_or_ids) == 0:
        print("get all elf clusters, clusters: {}".format(clusters))
        return clusters
    clusters = [cluster for cluster in clusters if cluster.get("name") in names_or_ids or cluster.get("id") in names_or_ids ]
    print("get elf clusters by names or ids, clusters: {}".format(clusters))
    return clusters

def getObservabilityInstances():
    """
    getObservabilityInstance returns the observability instances
    Example:
    {
    "operationName": "observabilityInstanceAndApps",
    "variables": {},
    "query": "query observabilityInstanceAndApps {\n  bundleApplicationInstances {\n    id\n    name\n    status\n    application {\n      id\n      instances {\n        id\n        vm {\n          id\n          status\n          cpu_usage\n          memory_usage\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    vm_spec {\n      ip\n      subnet_mask\n      gateway\n      vlan_id\n      vcpu_count\n      memory_size_bytes\n      storage_size_bytes\n      __typename\n    }\n    description\n    connected_clusters {\n      id\n      name\n      status\n      migration_status\n      cluster {\n        id\n        name\n        hosts {\n          id\n          name\n          __typename\n        }\n        type\n        __typename\n      }\n      host_plugin {\n        id\n        host_plugin_instances\n        __typename\n      }\n      observability_connected_cluster {\n        id\n        traffic_enabled\n        status\n        __typename\n      }\n      __typename\n    }\n    bundle_application_package {\n      id\n      version\n      arch\n      __typename\n    }\n    health_status\n    connected_system_services {\n      id\n      type\n      tenant_id\n      system_service {\n        id\n        name\n        __typename\n      }\n      instances {\n        state\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"
    }
    """
    return graphqlRequest(TOWERURL,
                          """
                          query observabilityInstanceAndApps {
                            bundleApplicationInstances {
                              id
                              name
                              status
                              vm_spec {
                                ip
                              }
                              connected_clusters {
                                id
                                name
                                status
                                observability_connected_cluster {
                                  id
                                  traffic_enabled
                                  status
                                  __typename
                                }
                                __typename
                              }
                            }
                          }
                          """,
                          "bundleApplicationInstances",
                          {})

def buildExportFlowsTaskData(from_time, to_time, cluster_ids, network_type, filter_low_bandwidth, time_zone, file_name, filename_prifix):
    """
    buildExportFlowsTaskData returns a json object as query request body for export flows task
    """
    filters = []

    filters.append({
        "name": "protocol",
        "type": "set",
        "value": [
            "TCP",
            "UDP",
            "ICMP"
        ]
    })

    src_or_dst_filters = []
    if cluster_ids is not None and len(cluster_ids) > 0:
        src_or_dst_filters.append({
            "name": "cluster_id",
            "type": "set",
            "value": cluster_ids
        })

    if network_type is not None:
        src_or_dst_filters.append({
            "name": "network_type",
            "type": "equal",
            "value": network_type
        })
    
    if src_or_dst_filters is not None and len(src_or_dst_filters) > 0:
        filters.append({
            "name": "src_or_dst",
            "type": "group",
            "value": src_or_dst_filters
        })

    if time_zone is None:
        time_zone = "Asia/Shanghai"
    
    if file_name is None:
        file_name = "{}+{}-{}".format(filename_prifix, from_time, to_time)
    
    data ={
        "time": {
            "from": from_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "to": to_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        },
        "filters": filters,
        "option": {
            "filter_low_bandwidth": filter_low_bandwidth,
            "replace": {
                "id": {
                    "to": "id"
                },
                "last_update_timestamp": {
                    "to": "时间"
                },
                "src_name": {
                    "to": "源端"
                },
                "src_ip": {
                    "to": "源端 IP 地址"
                },
                "src_port": {
                    "to": "源端端口号"
                },
                "dst_name": {
                    "to": "目标端"
                },
                "dst_ip": {
                    "to": "目标端 IP 地址"
                },
                "dst_port": {
                    "to": "目标端端口号"
                },
                "protocol": {
                    "to": "通信协议"
                },
                "traffic_type": {
                    "to": "流量类型",
                    "data": {
                        "Default": "默认允许",
                        "Unprotected": "未保护",
                        "Protected": "已保护",
                        "Rejected": "已拒绝"
                    }
                },
                "expected_traffic_type": {
                    "to": "预期类型",
                    "data": {
                        "None": "-",
                        "Default": "-",
                        "Unprotected": "-",
                        "Protected": "预期被保护",
                        "Rejected": "预期被拒绝"
                    }
                },
                "origin_packets": {
                    "to": "发包数"
                },
                "origin_bits": {
                    "to": "发送数据量（b）"
                },
                "origin_bits_per_second": {
                    "to": "发送带宽（bps）"
                },
                "reverse_packets": {
                    "to": "收包数"
                },
                "reverse_bits": {
                    "to": "接收数据量（b）"
                },
                "reverse_bits_per_second": {
                    "to": "接收带宽（bps）"
                },
                "packets_per_second": {
                    "to": "包转发率（pps）"
                }
            },
            "enabled_fields": [
                "id",
                "last_update_timestamp",
                "src_name",
                "src_ip",
                "src_port",
                "dst_name",
                "dst_ip",
                "dst_port",
                "protocol",
                "origin_packets",
                "origin_bits",
                "origin_bits_per_second",
                "reverse_packets",
                "reverse_bits",
                "reverse_bits_per_second",
                "packets_per_second"
            ]
        },
        "timezone": time_zone,
        "filename": file_name
    }

    if DEBUG:
        print("build export flows task data successfully, data: {}".format(data))

    return data

def build_queryloader_async_export_body(from_time, to_time, cluster_ids, network_type, filter_low_bandwidth, time_zone, file_name, filename_prifix):
    """
    Body for POST .../traffic-visualization/async/export/table (queryloader async translator).
    GraphQL export input uses top-level timezone/filename; queryloader expects option.time_zone and option.file_name.
    """
    data = buildExportFlowsTaskData(
        from_time, to_time, cluster_ids, network_type, filter_low_bandwidth, time_zone, file_name, filename_prifix
    )
    option = dict(data["option"])
    option["time_zone"] = data["timezone"]
    option["file_name"] = data["filename"]
    return {
        "time": data["time"],
        "filters": data["filters"],
        "option": option,
    }

def _read_http_response(resp):
    raw = resp.read()
    if sys.version_info.major == 3 and isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    return resp.status, raw

def tower_ovm_tv_path(ovm_ip, suffix):
    if not suffix.startswith("/"):
        suffix = "/" + suffix
    return "/api/ovm/{}/traffic-visualization{}".format(ovm_ip, suffix)

def ovm_proxy_get_json(ovm_ip, suffix):
    path = tower_ovm_tv_path(ovm_ip, suffix)
    headers = {"Authorization": TOKEN}
    resp = request(TOWERURL, path, "GET", None, headers)
    status, text = _read_http_response(resp)
    if status != 200:
        raise Exception("Tower proxy GET {} HTTP {}: {}".format(path, status, text))
    try:
        return json.loads(text)
    except Exception:
        raise Exception("Tower proxy GET non-JSON: {}".format(text))

def ovm_proxy_list_async_requests(ovm_ip):
    return ovm_proxy_get_json(ovm_ip, "/internal/async/requests")

def ovm_proxy_get_request_status(ovm_ip, request_id):
    return ovm_proxy_get_json(ovm_ip, "/internal/async/request/{}".format(request_id))

def _ovm_proxy_delete_no_content(path):
    """DELETE expecting 200/204; 404 treated as already removed (idempotent cleanup)."""
    headers = {"Authorization": TOKEN}
    resp = request(TOWERURL, path, "DELETE", None, headers)
    status, text = _read_http_response(resp)
    if status in (200, 204, 404):
        return status
    raise Exception("Tower proxy DELETE {} HTTP {}: {}".format(path, status, text))


def ovm_proxy_delete_async_request(ovm_ip, request_id):
    path = tower_ovm_tv_path(ovm_ip, "/internal/async/request/{}".format(request_id))
    return _ovm_proxy_delete_no_content(path)


def ovm_proxy_delete_async_task(ovm_ip, task_id):
    """DELETE /internal/async/task/{task_id} (queryloader); use after export to drop task status/cache."""
    path = tower_ovm_tv_path(ovm_ip, "/internal/async/task/{}".format(task_id))
    return _ovm_proxy_delete_no_content(path)

def ovm_proxy_download_export(ovm_ip, task_id, output_path):
    path = tower_ovm_tv_path(ovm_ip, "/download/{}".format(task_id))
    headers = {"Authorization": TOKEN}
    resp = request(TOWERURL, path, "GET", None, headers)
    status = resp.status
    raw = resp.read()
    if status != 200:
        if sys.version_info.major == 3 and isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        raise Exception("Tower proxy download HTTP {}: {}".format(status, raw))
    mode = "wb"
    with open(output_path, mode) as out:
        out.write(raw)
    return len(raw)

def export_flows_ovm_proxy_async(ovm_ip, body_dict):
    """
    POST /api/ovm/{ovm_ip}/traffic-visualization/async/export/table via Tower HTTPS proxy.
    Returns parsed JSON object on HTTP 200, else raises Exception.
    """
    path = tower_ovm_tv_path(ovm_ip, "/async/export/table")
    body = json.dumps(body_dict)
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        "Authorization": TOKEN,
    }
    resp = request(TOWERURL, path, "POST", body, headers)
    status, text = _read_http_response(resp)
    if status != 200:
        raise Exception("Tower proxy export HTTP {}: {}".format(status, text))
    try:
        return json.loads(text)
    except Exception:
        raise Exception("Tower proxy export non-JSON body: {}".format(text))


def run_sync_proxy_export(ovm_ip, body_ql, output_path, poll_interval_sec, timeout_sec):
    """
    Create proxy async export, poll GET .../internal/async/request/{id} until task ready,
    download CSV to output_path, then DELETE the async request and the export task. For small exports only.
    """
    request_id = None
    task_id_for_cleanup = None
    try:
        rsp = export_flows_ovm_proxy_async(ovm_ip, body_ql)
        request_id = rsp.get("id")
        if not request_id:
            raise Exception("sync export: missing request id in response")

        def task_state_from_response(obj):
            ts = obj.get("task_status") or {}
            return ts.get("id"), ts.get("ready"), ts.get("error")

        task_id, ready, err = task_state_from_response(rsp)
        if task_id:
            task_id_for_cleanup = task_id
        if err:
            raise Exception("sync export failed: {}".format(err))
        deadline = time.time() + float(timeout_sec)
        while (not ready or not task_id) and time.time() < deadline:
            time.sleep(float(poll_interval_sec))
            st = ovm_proxy_get_request_status(ovm_ip, request_id)
            task_id, ready, err = task_state_from_response(st)
            if task_id:
                task_id_for_cleanup = task_id
            if err:
                raise Exception("sync export failed: {}".format(err))
        if not ready or not task_id:
            raise Exception(
                "sync export timed out after {}s (use larger --sync-timeout or non-sync export)".format(
                    timeout_sec
                )
            )

        n = ovm_proxy_download_export(ovm_ip, task_id, output_path)
        print("sync export downloaded {} bytes to {}".format(n, output_path))
        return n
    finally:
        if request_id:
            try:
                ovm_proxy_delete_async_request(ovm_ip, request_id)
                if DEBUG:
                    print("sync export cleaned up request {}".format(request_id))
            except Exception as ex:
                print("warning: sync export cleanup DELETE request failed: {}".format(ex))
        if task_id_for_cleanup:
            try:
                ovm_proxy_delete_async_task(ovm_ip, task_id_for_cleanup)
                if DEBUG:
                    print("sync export cleaned up task {}".format(task_id_for_cleanup))
            except Exception as ex:
                print("warning: sync export cleanup DELETE task failed: {}".format(ex))


def exportFlowsTask(instance_id, data):
    """
    export flows task
    Args:
        instance_id: the instance id of the flow
        time_zone: the time zone of the flow
        file_name: the name of the file
        from_time: the start time of the flow
        to_time: the end time of the flow
    Returns: task id(UUID string) if success, otherwise None
    """
    return graphqlRequest(TOWERURL,
                          """
                          mutation createTrafficVisualizationExportTask($where: BundleApplicationInstanceWhereUniqueInput!, $data: TrafficVisualizationExportTaskCreateInput!) {
                              createTrafficVisualizationExportTask(where: $where, data: $data) {
                                  id
                              }
                          }
                          """,
                          "createTrafficVisualizationExportTask",
                          {"where": {"id": instance_id}, "data": data}).get("id", None)

def exportFlowsTasks(obs_ref, from_time, to_time, cluster_ids, network_type, filter_low_bandwidth, time_zone, file_name, filename_prifix):
    instances = select_observability_instances(getObservabilityInstances(), obs_ref)
    for instance in instances:
        data = buildExportFlowsTaskData(from_time, to_time, cluster_ids, network_type, filter_low_bandwidth, time_zone, file_name, filename_prifix)
        task_id = exportFlowsTask(instance.get("id"), data)
        if task_id is not None:
            print("export flows task successfully, task id: {}".format(task_id))
        else:
            print("export flows task failed, instance id: {}".format(instance.get("id")))

def login():
    global TOKEN
    source = LOGIN_TYPE
    resp = graphqlRequest(
        TOWERURL,
        """
        mutation login($data:LoginInput!){
             login(data:$data){
                 token
             }
        }""",
        "login",
        {"data": {"username": USERNAME, "password": PASSWORD, "source": source}},
    )
    TOKEN = resp["token"]

def _norm_opt_str(s):
    if s is None:
        return None
    s = s.strip()
    return s if s else None

def main():
    global TOWERURL, USERNAME, PASSWORD, LOGIN_TYPE

    parse_args = get_parser().parse_args()
    
    # Load environment variables from .env file if provided
    if parse_args.env:
        load_env_file(parse_args.env)
    
    # Initialize environment variables
    init_env_vars()

    obs_ref = parse_single_obs_arg(parse_args.obs)
    create_tower_task = parse_args.create_tower_task

    ovm_status_id = _norm_opt_str(parse_args.request_status)
    ovm_download_task = _norm_opt_str(parse_args.download_task)
    ovm_delete_id = _norm_opt_str(parse_args.delete_request)
    ovm_op_count = 0
    if parse_args.list_requests:
        ovm_op_count += 1
    if ovm_status_id:
        ovm_op_count += 1
    if ovm_download_task:
        ovm_op_count += 1
    if ovm_delete_id:
        ovm_op_count += 1

    if ovm_op_count > 1:
        print("error: only one of --list-requests, --request-status, --download-task, --delete-request")
        exit(1)

    if parse_args.sync_export and ovm_op_count > 0:
        print(
            "error: --sync-export cannot be combined with --list-requests / --request-status / --download-task / --delete-request"
        )
        exit(1)

    global DEBUG
    DEBUG = parse_args.debug
    if DEBUG:
        print("DEBUG mode is enabled")

    if ovm_op_count == 1:
        if create_tower_task:
            print("error: --create-tower-task cannot be combined with --list-requests / --request-status / --download-task / --delete-request")
            exit(1)
        if TOKEN is None or TOKEN == "":
            login()
        all_inst = getObservabilityInstances()
        ovm_ip = resolve_proxy_admin_target_ip(obs_ref, all_inst)
        try:
            if parse_args.list_requests:
                print(json.dumps(ovm_proxy_list_async_requests(ovm_ip), indent=2))
            elif ovm_status_id:
                print(json.dumps(ovm_proxy_get_request_status(ovm_ip, ovm_status_id), indent=2))
            elif ovm_download_task:
                out_path = _norm_opt_str(parse_args.output)
                if not out_path:
                    print("error: --download-task requires --output")
                    exit(1)
                n = ovm_proxy_download_export(ovm_ip, ovm_download_task, out_path)
                print("downloaded {} bytes to {}".format(n, out_path))
            elif ovm_delete_id:
                ovm_proxy_delete_async_request(ovm_ip, ovm_delete_id)
                print("delete request {} ok".format(ovm_delete_id))
            else:
                print("error: internal proxy operation dispatch")
                exit(1)
        except Exception as e:
            print("proxy operation failed: {}".format(e))
            exit(1)
        return

    from_time = parse_args.from_time
    to_time = parse_args.to_time

    if to_time is None:
        to_time = datetime.datetime.now()
    else:
        try:
            to_time = parse_rfc3339_timestamp(to_time)
        except ValueError as e:
            print("to_time: {}".format(e))
            exit(1)

    if from_time is None:
        from_time = to_time - datetime.timedelta(days=1)
    else:
        try:
            from_time = parse_rfc3339_timestamp(from_time)
        except ValueError as e:
            print("from_time: {}".format(e))
            exit(1)

    if from_time >= to_time:
        print("from_time must be before to_time, from_time: {}, to_time: {}".format(from_time, to_time))
        exit(1)

    cluster_names_or_ids = parse_args.clusters
    if cluster_names_or_ids is not None:
        cluster_names_or_ids = cluster_names_or_ids.split(",")
    network_type = parse_args.network_type
    filter_low_bandwidth = parse_args.filter_low_bandwidth
    time_zone = parse_args.time_zone
    file_name = parse_args.file_name
    file_name_prefix = parse_args.file_name_prefix
    if file_name_prefix is None:
        file_name_prefix = "export-flows"

    if file_name is None and file_name_prefix is None:
        print("conflicting arguments provided, --file_name and --filename_prefix cannot be used together")
        exit(1)

    if TOKEN is None or TOKEN == "":
        login()

    if parse_args.sync_export:
        if create_tower_task:
            print("error: --sync-export only works with Tower proxy async export, not --create-tower-task")
            exit(1)
        out_path = _norm_opt_str(parse_args.output)
        if not out_path:
            print("error: --sync-export requires --output")
            exit(1)
        clusters = get_elf_clusters_by_names_or_ids(cluster_names_or_ids)
        print("clusters: {}".format(clusters))
        cluster_ids = [cluster.get("id") for cluster in clusters]
        all_inst = getObservabilityInstances()
        ovm_ip = resolve_proxy_admin_target_ip(obs_ref, all_inst)
        body_ql = build_queryloader_async_export_body(
            from_time,
            to_time,
            cluster_ids,
            network_type,
            filter_low_bandwidth,
            time_zone,
            file_name,
            file_name_prefix,
        )
        try:
            run_sync_proxy_export(
                ovm_ip,
                body_ql,
                out_path,
                parse_args.sync_poll_interval,
                parse_args.sync_timeout,
            )
        except Exception as e:
            print("sync export failed: {}".format(e))
            exit(1)
        return

    clusters = get_elf_clusters_by_names_or_ids(cluster_names_or_ids)
    print("clusters: {}".format(clusters))
    cluster_ids = [cluster.get("id") for cluster in clusters]

    if create_tower_task:
        instances = select_observability_instances(
            getObservabilityInstances(), obs_ref
        )
        if DEBUG:
            print("observability instances for export: {}".format(instances))
        for instance in instances:
            if instance.get("status") != "SUCCESS":
                print("skip exporting flows for instance: {} because it is not in SUCCESS status".format(instance.get("name")))
                continue
            skip_export = True
            if skip_export:
                for connected_cluster in instance.get("connected_clusters"):
                    occ = connected_cluster.get("observability_connected_cluster")
                    if occ is None or (occ.get("traffic_enabled") and occ.get("status") == "SUCCESS"):
                        skip_export = False
                        break
            if skip_export:
                print("skip exporting flows for instance: {} because there is not a healthy and enabled traffic visualization connected cluster".format(instance.get("name")))
                continue
            print("exporting flows for instance: {}".format(instance.get("name")))
            try:
                data = buildExportFlowsTaskData(from_time, to_time, cluster_ids, network_type, filter_low_bandwidth, time_zone, file_name, file_name_prefix)
                task_id = exportFlowsTask(instance.get("id"), data)
                if task_id is not None:
                    print("export flows task successfully, task id: {}".format(task_id))
                else:
                    print("export flows task failed, instance id: {}".format(instance.get("id")))
            except Exception as e:
                print("export flows task failed, instance id: {}, error: {}".format(instance.get("id"), e))
    else:
        all_inst = getObservabilityInstances()
        proxy_targets = resolve_proxy_target_ips(obs_ref, all_inst)
        if not proxy_targets:
            print(
                "error: no management IP (vm_spec.ip) found for proxy export; set --obs or fix Tower data"
            )
            exit(1)
        for ovm_ip, label in proxy_targets:
            print("exporting flows via Tower proxy, target: {}, ip: {}".format(label, ovm_ip))
            try:
                body_ql = build_queryloader_async_export_body(
                    from_time,
                    to_time,
                    cluster_ids,
                    network_type,
                    filter_low_bandwidth,
                    time_zone,
                    file_name,
                    file_name_prefix,
                )
                if DEBUG:
                    print("proxy export request body: {}".format(body_ql))
                rsp = export_flows_ovm_proxy_async(ovm_ip, body_ql)
                print(
                    "proxy async export accepted, response: {}".format(json.dumps(rsp))
                )
            except Exception as e:
                print("proxy export failed, error: {}".format(e))



if __name__ == "__main__":
    main()
