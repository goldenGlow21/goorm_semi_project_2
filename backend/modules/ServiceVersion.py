import re
import socket
import time
import requests
from os import cpu_count
from typing import Dict, Optional, List
from concurrent.futures import ThreadPoolExecutor



class ServiceProbeParser:
    def __init__(self, probe_file_path):
        self.probe_file_path = probe_file_path
        self.probes = []
        self.parse_probes()

    def parse_probes(self):
        current_probe = None

        with open(self.probe_file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                line = line.strip()

                if not line or line.startswith('#'):
                    continue

                if line.startswith('Probe '):
                    if current_probe:
                        self.probes.append(current_probe)
                    current_probe = self._parse_probe_line(line)

                elif line.startswith('match ') and current_probe:
                    match = self._parse_match_line(line)
                    if match:
                        if 'matches' not in current_probe:
                            current_probe['matches'] = []
                        current_probe['matches'].append(match)

            if current_probe:
                self.probes.append(current_probe)

    def _parse_probe_line(self, line: str) -> Dict:
        parts = line.split(' ')
        probe = {
            'protocol': parts[1],
            'name': parts[2].strip('"'),
            'probe_string': None,
            'matches': []
        }

        if 'q|' in line:
            start = line.index('q|') + 2
            end = line.rindex('|')
            probe['probe_string'] = line[start:end]

        return probe

    def _parse_match_line(self, line: str) -> Optional[Dict]:
        try:
            pattern_start = line.index('m|') + 2
            pattern_end = line.index('|', pattern_start)
            pattern = line[pattern_start:pattern_end]

            flags = re.IGNORECASE | re.DOTALL
            if 's' in line[pattern_end + 1:pattern_end + 3]:
                flags |= re.DOTALL

            version_info = {}
            remaining = line[pattern_end + 1:]

            # Parse service name (p/)
            if 'p/' in remaining:
                service_match = re.search(r'p/([^/]+)/', remaining)
                if service_match:
                    version_info['service'] = service_match.group(1)

            # Parse version (v/)
            if 'v/' in remaining:
                version_match = re.search(r'v/([^/]+)/', remaining)
                if version_match:
                    version_info['version_pattern'] = version_match.group(1)

            # Parse additional info (i/)
            if 'i/' in remaining:
                info_match = re.search(r'i/([^/]+)/', remaining)
                if info_match:
                    version_info['info'] = info_match.group(1)
            if 'cpe:/' in remaining:
                cpe_match = re.search(r'cpe:/([^/\s]+(?:/[^/\s]+)*)', remaining)
                if cpe_match:
                    cpe_str = 'cpe:' + cpe_match.group(1)
                    # Remove trailing '/a' if present
                    cpe_str = cpe_str.replace('/a', '')
                    version_info['cpe'] = cpe_str

            binary_pattern = self._convert_pattern_to_binary(pattern)

            return {
                'pattern': pattern,
                'binary_pattern': binary_pattern,
                'pattern_compiled': re.compile(pattern, flags),
                'version_info': version_info
            }
        except Exception:
            return None

    def _convert_pattern_to_binary(self, pattern: str) -> bytes:
        try:
            pattern = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), pattern)
            pattern = pattern.replace('\\0', '\0')
            pattern = pattern.encode('latin1').decode('unicode-escape').encode('latin1')
            return pattern
        except:
            return pattern.encode('latin1')


class ServiceScanner:
    def __init__(self, service_parser):
        self.parser = service_parser

    def multi_threading_scan(self, target_ip, ports):
        with ThreadPoolExecutor(max_workers=cpu_count() * 2) as executor:
            # 멀티스레드 스캔 실행
            results = list(executor.map(lambda port: self.scan_port(target_ip, port), ports))
            print(results)
        return results

    def scan_port(self, ip: str, port: int, timeout: float = 2) -> Dict:
        result = {
            'port': port,
            'state': 'closed',
            'service': None,
            'version': None,
            'cpe': None,
            'info': None
        }

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) == 0:
                    result['state'] = 'open'

                    # Try each probe
                    for probe in self.parser.probes:
                        service_info = self._try_probe(ip, port, probe, timeout)
                        if service_info:
                            result.update(service_info)
                            break

        except socket.error as e:
            result['state'] = 'error'
            result['error'] = str(e)

        return result

    def _try_probe(self, ip: str, port: int, probe: Dict, timeout: float) -> Optional[Dict]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((ip, port))

                # Send probe string if exists
                if probe['probe_string']:
                    probe_bytes = self._format_probe_string(probe['probe_string'])
                    sock.send(probe_bytes)

                response = self._receive_with_timeout(sock, timeout)

                # Try to match response against all patterns
                if response:
                    return self._match_response(response, probe['matches'])

        except socket.error:
            pass

        return None

    def _receive_with_timeout(self, sock: socket.socket, timeout: float) -> bytes:
        total_data = b''
        start_time = time.time()

        while True:
            if time.time() - start_time > timeout:
                break

            try:
                sock.settimeout(0.5)
                data = sock.recv(2048)
                if not data:
                    break
                total_data += data
                if len(total_data) > 4096:
                    break
            except socket.timeout:
                break
            except socket.error:
                break

        return total_data

    def _format_probe_string(self, probe_string: str) -> bytes:
        if not probe_string:
            return b""
        try:
            probe_string = probe_string.replace('\\n', '\n').replace('\\r', '\r')
            return bytes(probe_string, 'utf-8').decode('unicode-escape').encode()
        except:
            return probe_string.encode()

    def _match_response(self, response: bytes, matches: List[Dict]) -> Optional[Dict]:
        for match in matches:
            try:
                # Try binary pattern matching
                pattern_match = None
                response_str = None

                if match['binary_pattern']:
                    if re.search(match['binary_pattern'], response, re.DOTALL):
                        response_str = response.decode('latin1', errors='ignore')
                        pattern_match = match['pattern_compiled'].search(response_str)

                if not pattern_match:
                    response_str = response.decode('latin1', errors='ignore')
                    pattern_match = match['pattern_compiled'].search(response_str)

                if pattern_match:
                    version_info = match['version_info'].copy()
                    service_info = {}

                    # Extract service name
                    if 'service' in version_info:
                        service_info['service'] = version_info['service']

                    # Extract version
                    if 'version_pattern' in version_info:
                        version_str = version_info['version_pattern']
                        for i, group in enumerate(pattern_match.groups(), 1):
                            if group:
                                version_str = version_str.replace(f'${i}', group)
                        service_info['version'] = version_str

                    # Extract CPE
                    if 'cpe' in version_info:
                        cpe_str = version_info['cpe']
                        for i, group in enumerate(pattern_match.groups(), 1):
                            if group:
                                cpe_str = cpe_str.replace(f'${i}', group)
                        service_info['cves'] = self.search_cves(cpe_str)

                    # Extract additional info
                    if 'info' in version_info:
                        info_str = version_info['info']
                        for i, group in enumerate(pattern_match.groups(), 1):
                            if group:
                                info_str = info_str.replace(f'${i}', group)
                        service_info['info'] = info_str

                    return service_info

            except Exception:
                continue

        return None

    def search_cves(self, cpe23, limit=10):
        cpe23 = cpe23.replace(":", ":2.3:", 1)
        results = []
        url = "https://cvedb.shodan.io/cves"
        params = {
            "cpe23": cpe23,
            "sort_by_epss": "true",
            "limit": limit
        }
        response = requests.get(url, params=params)
        if response.status_code != 200:
            return None
        cves = response.json()
        for cve in cves.get("cves"):
            cve_id = cve.get("cve_id")
            summary = cve.get("summary")
            cvss = cve.get("cvss")
            ranking_epss = cve.get("ranking_epss")
            results.append({
                "cve_id": cve_id,
                "summary": summary,
                "cvss": cvss,
                "ranking_epss": ranking_epss
            })
        return results


def main():
    try:
        print("Service Version Scanner")
        print("=" * 50)

        TARGET_IP = "13.125.143.118"
        TARGET_PORTS = [21, 22, 80, 443, 3306, 8000, 8080]

        parser = ServiceProbeParser('nmap-service-probes.txt')
        scanner = ServiceScanner(parser)

        print(f"\n대상 IP: {TARGET_IP}")
        print(f"스캔할 포트: {TARGET_PORTS}")
        print("\n스캔을 시작합니다...")

        start_time = time.time()
        results = scanner.multi_threading_scan(TARGET_IP, TARGET_PORTS)
        for result in results:
            print(f"\n포트 {result['port']} 스캔 중...")


            print(f"상태: {result['state']}")
            if result['state'] == 'open':
                print(f"서비스: {result['service'] or '알 수 없음'}")
                if result.get('version'):
                    print(f"버전: {result['version']}")
                if result.get('cves'):
                    print(f"CVES: {result['cves']}")
                if result.get('info'):
                    print(f"추가 정보: {result['info']}")
            elif result['state'] == 'error':
                print(f"에러: {result.get('error', '알 수 없는 에러')}")

        scan_time = time.time() - start_time
        print(f"\n스캔 완료 (소요시간: {scan_time:.2f}초)")

    except KeyboardInterrupt:
        print("\n\n스캔이 사용자에 의해 중단되었습니다.")
    except Exception as e:
        print(f"\n오류가 발생했습니다: {str(e)}")


if __name__ == "__main__":
    main()