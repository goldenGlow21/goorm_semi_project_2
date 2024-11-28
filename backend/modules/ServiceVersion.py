import re
import socket
import time

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
                    try:
                        match = self._parse_match_line(line)
                        if match:
                            if 'matches' not in current_probe:
                                current_probe['matches'] = []
                            current_probe['matches'].append(match)
                    except Exception:
                        pass
                        
            if current_probe:
                self.probes.append(current_probe)

    def _parse_probe_line(self, line):
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

    def _parse_match_line(self, line):
        try:
            pattern_start = line.index('m|') + 2
            pattern_end = line.index('|', pattern_start)
            pattern = line[pattern_start:pattern_end]
            
            version_info = {}
            remaining = line[pattern_end + 1:]
            
            if 'p/' in remaining:
                service_match = re.search(r'p/([^/]+)/', remaining)
                if service_match:
                    version_info['service'] = service_match.group(1)
            
            if 'v/' in remaining:
                version_match = re.search(r'v/([^/]+)/', remaining)
                if version_match:
                    version_str = version_match.group(1)
                    version_info['version_pattern'] = version_str
                    version_info['version'] = version_str
                
            return {
                'pattern': pattern,
                'version_info': version_info,
                'pattern_compiled': re.compile(pattern, re.IGNORECASE | re.DOTALL)
            }
        except Exception:
            return None

class ServiceScanner:
    def __init__(self, service_parser):
        self.parser = service_parser

    def scan_port(self, ip, port, timeout=2):
        result = {
            'port': port,
            'state': 'closed',
            'service': None,
            'version': None
        }
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    result['state'] = 'open'
                    
                    for probe in self.parser.probes:
                        try:
                            if probe['probe_string']:
                                s.send(self._format_probe_string(probe['probe_string']))
                            response = s.recv(1024)
                            
                            service_info = self._match_response(response, probe['matches'])
                            if service_info:
                                result.update(service_info)
                                break
                                
                        except socket.error:
                            continue
                            
        except socket.error as e:
            result['state'] = 'error'
            result['error'] = str(e)
            
        return result

    def _format_probe_string(self, probe_string):
        if not probe_string:
            return b""
        return bytes(probe_string, 'utf-8').decode('unicode-escape').encode()

    def _match_response(self, response, matches):
        response_str = response.decode('utf-8', errors='ignore')
        
        for match in matches:
            try:
                pattern_match = match['pattern_compiled'].search(response_str)
                if pattern_match:
                    version_info = match['version_info'].copy()
                    
                    if 'version_pattern' in version_info:
                        try:
                            version_pattern = version_info['version_pattern']
                            for i, group in enumerate(pattern_match.groups(), 1):
                                if group:
                                    version_pattern = version_pattern.replace(f'${i}', group)
                            version_info['version'] = version_pattern
                        except Exception:
                            pass
                    
                    return {
                        'service': version_info.get('service'),
                        'version': version_info.get('version')
                    }
            except Exception:
                continue
                
        return None

def main():
    try:
        print("Service Version Scanner")
        print("=" * 50)
        
        # 스캔할 IP 주소와 포트 지정
        TARGET_IP = "13.125.143.118"  # 스캔할 IP 주소
        TARGET_PORTS = [20, 21, 22, 53, 80, 443, 8080]  # 스캔할 포트 목록
        
        parser = ServiceProbeParser('nmap-service-probes.txt')
        scanner = ServiceScanner(parser)
        
        print(f"\n대상 IP: {TARGET_IP}")
        print(f"스캔할 포트: {TARGET_PORTS}")
        print("\n스캔을 시작합니다...")
        start_time = time.time()
        
        for port in TARGET_PORTS:
            print(f"\n포트 {port} 스캔 중...")
            result = scanner.scan_port(TARGET_IP, port)
            
            print(f"상태: {result['state']}")
            if result['state'] == 'open':
                service = result['service'] or '알 수 없음'
                version = result['version'] or '알 수 없음'
                print(f"서비스: {service}")
                print(f"버전: {version}")
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
