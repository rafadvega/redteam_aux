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
        original_offset = offset
        
        while i < len(data) and data[i] != 0:
            length = data[i]
            
            # Verificar si es un puntero (compresión DNS)
            if (length & 0xC0) == 0xC0:
                if i + 1 < len(data):
                    pointer = ((length & 0x3F) << 8) | data[i + 1]
                    # Recursivamente parsear desde el puntero
                    pointed_domain, _ = self.parse_domain_name(data, pointer)
                    if pointed_domain:
                        domain_parts.append(pointed_domain)
                    return '.'.join(domain_parts), i + 2
                else:
                    break
            
            i += 1
            if i + length <= len(data):
                try:
                    domain_parts.append(data[i:i+length].decode('utf-8'))
                    i += length
                except UnicodeDecodeError:
                    # Si hay error de decodificación, salir
                    break
            else:
                break
        
        return '.'.join(domain_parts), i + 1 if i < len(data) else len(data)
    
    def encode_domain_name(self, domain):
        """Codifica un nombre de dominio en formato DNS"""
        if not domain or domain == '.':
            return b'\x00'
        
        encoded = b''
        for part in domain.split('.'):
            if part:  # Evitar partes vacías
                part_bytes = part.encode('utf-8')
                if len(part_bytes) > 63:  # Límite DNS
                    part_bytes = part_bytes[:63]
                encoded += struct.pack('!B', len(part_bytes))
                encoded += part_bytes
        encoded += struct.pack('!B', 0)  # Fin del nombre
        return encoded
    
    def build_response(self, query_data, domain, query_type, query_class):
        """Construye la respuesta DNS"""
        if len(query_data) < 12:
            raise ValueError("Query demasiado corta")
        
        # Header de respuesta
        transaction_id = query_data[0:2]
        
        # Flags de respuesta más completos
        # QR=1 (respuesta), Opcode=0 (query estándar), AA=1 (autoritativo), 
        # TC=0 (no truncado), RD=1 (recursión deseada), RA=1 (recursión disponible),
        # Z=0 (reservado), RCODE=0 (sin error)
        flags = 0x8580  # 1000 0101 1000 0000
        
        # Construir header completo
        response = bytearray()
        response.extend(transaction_id)                    # Transaction ID
        response.extend(struct.pack('!H', flags))          # Flags
        response.extend(struct.pack('!H', 1))              # Questions = 1
        response.extend(struct.pack('!H', 1))              # Answers = 1
        response.extend(struct.pack('!H', 0))              # Authority RRs = 0
        response.extend(struct.pack('!H', 0))              # Additional RRs = 0
        
        # Sección de pregunta (copiar desde query original)
        question_start = 12
        domain_name, question_end = self.parse_domain_name(query_data, question_start)
        
        # Verificar que tenemos suficientes datos para tipo y clase
        if question_end + 4 > len(query_data):
            raise ValueError("Query malformada: faltan datos de tipo/clase")
        
        # Copiar la pregunta completa desde el query original
        question_section = query_data[question_start:question_end + 4]
        response.extend(question_section)
        
        # Sección de respuesta
        # Usar compresión DNS apuntando al nombre en la pregunta
        response.extend(struct.pack('!H', 0xC00C))         # Puntero al nombre (offset 12)
        response.extend(struct.pack('!H', query_type))     # Tipo
        response.extend(struct.pack('!H', query_class))    # Clase
        response.extend(struct.pack('!I', 300))            # TTL
        
        # Datos de respuesta según el tipo
        response_value = ""
        
        if query_type == 1:  # A record (IPv4)
            ip_parts = self.default_ip.split('.')
            if len(ip_parts) != 4:
                raise ValueError("IP inválida")
            
            ip_bytes = b''.join(struct.pack('!B', int(part)) for part in ip_parts)
            response.extend(struct.pack('!H', 4))          # Longitud de datos
            response.extend(ip_bytes)
            response_value = self.default_ip
        
        elif query_type == 28:  # AAAA record (IPv6)
            # Convertir ::1 a 16 bytes
            ipv6_bytes = b'\x00' * 15 + b'\x01'
            response.extend(struct.pack('!H', 16))         # Longitud de datos
            response.extend(ipv6_bytes)
            response_value = self.default_ipv6
        
        elif query_type == 15:  # MX record
            mx_domain = f"mail.{domain}" if domain else "mail.localhost"
            mx_encoded = self.encode_domain_name(mx_domain)
            mx_data = struct.pack('!H', 10) + mx_encoded   # Prioridad + dominio
            response.extend(struct.pack('!H', len(mx_data)))
            response.extend(mx_data)
            response_value = f"10 {mx_domain}"
        
        elif query_type == 5:  # CNAME record
            cname_target = f"canonical.{domain}" if domain else "canonical.localhost"
            cname_encoded = self.encode_domain_name(cname_target)
            response.extend(struct.pack('!H', len(cname_encoded)))
            response.extend(cname_encoded)
            response_value = cname_target
        
        elif query_type == 16:  # TXT record
            txt_data = f"v=spf1 a mx include:_spf.{domain} ~all" if domain else "v=spf1 a mx ~all"
            txt_bytes = txt_data.encode('utf-8')
            # TXT records necesitan longitud de string antes del contenido
            txt_record = struct.pack('!B', len(txt_bytes)) + txt_bytes
            response.extend(struct.pack('!H', len(txt_record)))
            response.extend(txt_record)
            response_value = f'"{txt_data}"'
        
        elif query_type == 2:  # NS record
            ns_domain = f"ns1.{domain}" if domain else "ns1.localhost"
            ns_encoded = self.encode_domain_name(ns_domain)
            response.extend(struct.pack('!H', len(ns_encoded)))
            response.extend(ns_encoded)
            response_value = ns_domain
        
        elif query_type == 12:  # PTR record
            ptr_target = f"host.{domain}" if domain else "host.localhost"
            ptr_encoded = self.encode_domain_name(ptr_target)
            response.extend(struct.pack('!H', len(ptr_encoded)))
            response.extend(ptr_encoded)
            response_value = ptr_target
        
        else:  # Tipo no soportado - devolver NXDOMAIN
            # Cambiar RCODE a 3 (NXDOMAIN)
            flags_nxdomain = 0x8583
            response[2:4] = struct.pack('!H', flags_nxdomain)
            response[6:8] = struct.pack('!H', 0)  # Answers = 0
            response_value = "NXDOMAIN"
            return bytes(response), response_value
        
        return bytes(response), response_value
    
    def handle_query(self, data, addr, sock):
        """Maneja una consulta DNS"""
        try:
            # Validaciones básicas
            if len(data) < 12:
                raise ValueError("Paquete DNS demasiado corto")
            
            # Extraer información del header
            transaction_id = struct.unpack('!H', data[0:2])[0]
            flags = struct.unpack('!H', data[2:4])[0]
            
            # Verificar que es una query (QR bit = 0)
            if flags & 0x8000:
                raise ValueError("Recibida respuesta en lugar de query")
            
            # Extraer contadores
            qdcount = struct.unpack('!H', data[4:6])[0]
            
            if qdcount != 1:
                raise ValueError(f"Solo se soporta 1 pregunta, recibidas: {qdcount}")
            
            # Extraer dominio y tipo de consulta
            domain, end_pos = self.parse_domain_name(data, 12)
            
            if end_pos + 4 > len(data):
                raise ValueError("Query malformada")
            
            query_type = struct.unpack('!H', data[end_pos:end_pos+2])[0]
            query_class = struct.unpack('!H', data[end_pos+2:end_pos+4])[0]
            
            # Solo soportar clase IN (Internet)
            if query_class != 1:
                raise ValueError(f"Clase no soportada: {query_class}")
            
            # Mapeo de tipos de consulta para logging
            query_types = {
                1: 'A', 28: 'AAAA', 15: 'MX', 5: 'CNAME', 
                16: 'TXT', 2: 'NS', 6: 'SOA', 12: 'PTR'
            }
            type_name = query_types.get(query_type, f'TYPE{query_type}')
            
            # Log de consulta
            self.log_event({
                "event_type": "query",
                "client_ip": addr[0],
                "client_port": addr[1],
                "domain": domain,
                "query_type": type_name,
                "query_type_code": query_type,
                "query_class": query_class,
                "transaction_id": transaction_id,
                "query_size": len(data)
            })
            
            # Construir y enviar respuesta
            response, response_value = self.build_response(data, domain, query_type, query_class)
            sock.sendto(response, addr)
            
            # Log de respuesta
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
            # Log de error
            self.log_event({
                "event_type": "error",
                "client_ip": addr[0] if addr else "unknown",
                "client_port": addr[1] if addr else 0,
                "error": str(e),
                "error_type": type(e).__name__,
                "query_size": len(data) if data else 0
            })
            
            # Intentar enviar respuesta de error si es posible
            try:
                if len(data) >= 12:
                    error_response = bytearray(data[:2])  # Transaction ID
                    error_response.extend(struct.pack('!H', 0x8182))  # SERVFAIL
                    error_response.extend(data[4:12])  # Contadores originales
                    sock.sendto(bytes(error_response), addr)
            except:
                pass  # Si no se puede enviar error, ignorar
    
    def start(self):
        """Inicia el servidor DNS"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        
        print(f"🚀 Servidor DNS simple iniciado en {self.host}:{self.port}")
        print(f"📍 Respuestas por tipo:")
        print(f"   A     -> {self.default_ip}")
        print(f"   AAAA  -> {self.default_ipv6}")
        print(f"   MX    -> 10 mail.[domain]")
        print(f"   CNAME -> canonical.[domain]")
        print(f"   TXT   -> SPF record")
        print(f"   NS    -> ns1.[domain]")
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
