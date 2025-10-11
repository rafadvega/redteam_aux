import socket
import struct
import datetime
import json
import os

class SimpleDNSServer:
    def __init__(self, host='0.0.0.0', port=5353):
        self.host = host
        self.port = port
        self.default_ip = '127.0.0.1'
        self.default_ipv6 = '::1'
        self.default_domain = 'localhost'
        
        # Configurar archivo de log en el mismo directorio que el script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.log_file = os.path.join(script_dir, 'dns_queries.json')
        
        # Crear archivo de log si no existe
        self.init_log_file()
    
    def init_log_file(self):
        """Inicializa el archivo de log"""
        try:
            # Crear archivo si no existe
            if not os.path.exists(self.log_file):
                with open(self.log_file, 'w', encoding='utf-8') as f:
                    f.write('')
            
            # Log de inicio del servidor
            self.log_event({
                "event_type": "server_start",
                "message": "DNS Server iniciado",
                "server_host": self.host,
                "server_port": self.port,
                "default_ip": self.default_ip
            })
            
            print(f"📝 Logging JSON en: {self.log_file}")
        except Exception as e:
            print(f"❌ Error creando archivo de log: {e}")
    
    def log_event(self, event_data):
        """Escribe un evento en formato JSON en el archivo de log"""
        # Agregar timestamp
        event_data["timestamp"] = datetime.datetime.now().isoformat()
        
        try:
            # Escribir línea JSON en archivo
            with open(self.log_file, 'a', encoding='utf-8') as f:
                json.dump(event_data, f, ensure_ascii=False)
                f.write('\n')
            
            # También mostrar en consola (formato legible)
            self.print_console_log(event_data)
            
        except Exception as e:
            print(f"❌ Error escribiendo log: {e}")
    
    def print_console_log(self, event_data):
        """Muestra el log en consola de forma legible"""
        timestamp = event_data["timestamp"][:19].replace('T', ' ')
        
        if event_data["event_type"] == "query":
            print(f"[{timestamp}] QUERY    | {event_data['client_ip']:15} | {event_data['query_type']:6} | {event_data['domain']}")
        elif event_data["event_type"] == "response":
            response_value = event_data.get('response_value', event_data.get('response_ip', 'N/A'))
            print(f"[{timestamp}] RESPONSE | {event_data['client_ip']:15} | {event_data['query_type']:6} | {event_data['domain']} -> {response_value}")
        elif event_data["event_type"] == "error":
            print(f"[{timestamp}] ERROR    | {event_data.get('client_ip', 'unknown'):15} | ------ | {event_data['error']}")
        elif event_data["event_type"] == "server_start":
            print(f"[{timestamp}] SERVER   | {event_data['message']}")
        elif event_data["event_type"] == "server_stop":
            print(f"[{timestamp}] SERVER   | {event_data['message']}")
    
    def parse_domain_name(self, data, offset):
        """Extrae el nombre del dominio de la consulta DNS"""
        domain_parts = []
        i = offset
        
        while i < len(data) and data[i] != 0:
            length = data[i]
            i += 1
            if i + length <= len(data):
                domain_parts.append(data[i:i+length].decode('utf-8'))
                i += length
            else:
                break
        
        return '.'.join(domain_parts), i + 1
    
    def encode_domain_name(self, domain):
        """Codifica un nombre de dominio en formato DNS"""
        encoded = b''
        for part in domain.split('.'):
            encoded += struct.pack('!B', len(part))
            encoded += part.encode('utf-8')
        encoded += struct.pack('!B', 0)  # Fin del nombre
        return encoded
    
    def build_response(self, query_data, domain, query_type):
        """Construye la respuesta DNS"""
        # Copiar el header original y modificar flags
        response = bytearray(query_data[:2])  # Transaction ID
        response.extend(struct.pack('!H', 0x8180))  # Flags: respuesta estándar
        response.extend(query_data[4:12])  # Questions, Answers, Authority, Additional
        
        # Cambiar número de respuestas a 1
        response[6:8] = struct.pack('!H', 1)
        
        # Copiar la sección de pregunta completa
        i = 12
        while i < len(query_data) and query_data[i] != 0:
            i += 1
        i += 5  # Saltar el 0 final + tipo + clase
        
        response.extend(query_data[12:i])
        
        # Agregar la respuesta
        response.extend(struct.pack('!H', 0xC00C))  # Puntero al nombre
        response.extend(struct.pack('!H', query_type))  # Tipo de consulta
        response.extend(struct.pack('!H', 1))       # Clase IN
        response.extend(struct.pack('!I', 300))     # TTL
        
        # Datos de respuesta según el tipo
        response_value = ""
        
        if query_type == 1:  # A record (IPv4)
            response.extend(struct.pack('!H', 4))  # Longitud
            for part in self.default_ip.split('.'):
                response.extend(struct.pack('!B', int(part)))
            response_value = self.default_ip
        
        elif query_type == 28:  # AAAA record (IPv6)
            response.extend(struct.pack('!H', 16))  # Longitud
            # Convertir ::1 a bytes
            response.extend(b'\x00' * 15 + b'\x01')
            response_value = self.default_ipv6
        
        elif query_type == 15:  # MX record (Mail Exchange)
            mx_domain = f"mail.{domain}"
            mx_encoded = self.encode_domain_name(mx_domain)
            response.extend(struct.pack('!H', 2 + len(mx_encoded)))  # Longitud
            response.extend(struct.pack('!H', 10))  # Prioridad
            response.extend(mx_encoded)
            response_value = f"10 {mx_domain}"
        
        elif query_type == 5:  # CNAME record (Canonical Name)
            cname_target = f"canonical.{domain}"
            cname_encoded = self.encode_domain_name(cname_target)
            response.extend(struct.pack('!H', len(cname_encoded)))
            response.extend(cname_encoded)
            response_value = cname_target
        
        elif query_type == 16:  # TXT record
            txt_data = f"v=spf1 a mx include:_spf.{domain} ~all"
            txt_bytes = txt_data.encode('utf-8')
            response.extend(struct.pack('!H', len(txt_bytes) + 1))
            response.extend(struct.pack('!B', len(txt_bytes)))
            response.extend(txt_bytes)
            response_value = f'"{txt_data}"'
        
        elif query_type == 2:  # NS record (Name Server)
            ns_domain = f"ns1.{domain}"
            ns_encoded = self.encode_domain_name(ns_domain)
            response.extend(struct.pack('!H', len(ns_encoded)))
            response.extend(ns_encoded)
            response_value = ns_domain
        
        elif query_type == 6:  # SOA record (Start of Authority)
            primary_ns = f"ns1.{domain}"
            admin_email = f"admin.{domain}"
            
            primary_encoded = self.encode_domain_name(primary_ns)
            admin_encoded = self.encode_domain_name(admin_email)
            
            soa_data = primary_encoded + admin_encoded
            soa_data += struct.pack('!I', 2024011501)  # Serial
            soa_data += struct.pack('!I', 3600)       # Refresh
            soa_data += struct.pack('!I', 1800)       # Retry
            soa_data += struct.pack('!I', 604800)     # Expire
            soa_data += struct.pack('!I', 86400)      # Minimum TTL
            
            response.extend(struct.pack('!H', len(soa_data)))
            response.extend(soa_data)
            response_value = f"{primary_ns} {admin_email} 2024011501 3600 1800 604800 86400"
        
        elif query_type == 12:  # PTR record (Pointer)
            ptr_target = f"host.{domain}"
            ptr_encoded = self.encode_domain_name(ptr_target)
            response.extend(struct.pack('!H', len(ptr_encoded)))
            response.extend(ptr_encoded)
            response_value = ptr_target
        
        else:  # Tipos desconocidos - responder como A record
            response.extend(struct.pack('!H', 4))
            for part in self.default_ip.split('.'):
                response.extend(struct.pack('!B', int(part)))
            response_value = f"{self.default_ip} (fallback A record)"
        
        return bytes(response), response_value
    
    def handle_query(self, data, addr, sock):
        """Maneja una consulta DNS"""
        try:
            # Extraer información básica
            transaction_id = struct.unpack('!H', data[0:2])[0]
            
            # Extraer dominio y tipo de consulta
            domain, end_pos = self.parse_domain_name(data, 12)
            query_type = struct.unpack('!H', data[end_pos:end_pos+2])[0]
            
            # Mapeo de tipos de consulta para logging
            query_types = {
                1: 'A', 28: 'AAAA', 15: 'MX', 5: 'CNAME', 
                16: 'TXT', 2: 'NS', 6: 'SOA', 12: 'PTR'
            }
            type_name = query_types.get(query_type, f'TYPE{query_type}')
            
            # *** LOGGING DE CONSULTAS EN JSON ***
            self.log_event({
                "event_type": "query",
                "client_ip": addr[0],
                "client_port": addr[1],
                "domain": domain,
                "query_type": type_name,
                "query_type_code": query_type,
                "transaction_id": transaction_id,
                "query_size": len(data)
            })
            
            # Construir y enviar respuesta
            response, response_value = self.build_response(data, domain, query_type)
            sock.sendto(response, addr)
            
            # Log de la respuesta
            self.log_event({
                "event_type": "response",
                "client_ip": addr[0],
                "client_port": addr[1],
                "domain": domain,
                "query_type": type_name,
                "query_type_code": query_type,
                "response_value": response_value,
                "response_size": len(response),
                "ttl": 300
            })
                
        except Exception as e:
            self.log_event({
                "event_type": "error",
                "client_ip": addr[0] if addr else "unknown",
                "client_port": addr[1] if addr else 0,
                "error": str(e),
                "error_type": type(e).__name__
            })
    
    def start(self):
        """Inicia el servidor DNS"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host, self.port))
        
        print(f"🚀 Servidor DNS simple iniciado en {self.host}:{self.port}")
        print(f"📍 Respuestas por tipo:")
        print(f"   A     -> {self.default_ip}")
        print(f"   AAAA  -> {self.default_ipv6}")
        print(f"   MX    -> 10 mail.[domain]")
        print(f"   CNAME -> canonical.[domain]")
        print(f"   TXT   -> SPF record")
        print(f"   NS    -> ns1.[domain]")
        print(f"   SOA   -> Registro completo SOA")
        print(f"   PTR   -> host.[domain]")
        print(f"📝 Archivo de log JSON: {self.log_file}")
        print("=" * 60)
        
        try:
            while True:
                data, addr = sock.recvfrom(512)
                self.handle_query(data, addr, sock)
                
        except KeyboardInterrupt:
            self.log_event({
                "event_type": "server_stop",
                "message": "Servidor detenido por usuario",
                "reason": "keyboard_interrupt"
            })
            print("\n🛑 Deteniendo servidor DNS...")
        finally:
            sock.close()

if __name__ == "__main__":
    server = SimpleDNSServer()
    server.start()
