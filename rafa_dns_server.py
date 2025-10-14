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
    
    def parse_query_sections(self, data):
        """Parsea todas las secciones de la query incluyendo EDNS0"""
        if len(data) < 12:
            raise ValueError("Query demasiado corta")
        
        # Header
        header = struct.unpack('!HHHHHH', data[:12])
        transaction_id, flags, qdcount, ancount, nscount, arcount = header
        
        offset = 12
        questions = []
        additional = []
        
        # Parsear preguntas
        for _ in range(qdcount):
            domain, new_offset = self.parse_domain_name(data, offset)
            if new_offset + 4 > len(data):
                raise ValueError("Query malformada en sección de preguntas")
            
            qtype = struct.unpack('!H', data[new_offset:new_offset+2])[0]
            qclass = struct.unpack('!H', data[new_offset+2:new_offset+4])[0]
            
            questions.append({
                'domain': domain,
                'type': qtype,
                'class': qclass
            })
            offset = new_offset + 4
        
        # Saltar secciones de respuesta y autoridad si existen
        for _ in range(ancount + nscount):
            if offset >= len(data):
                break
            # Parsear nombre
            _, offset = self.parse_domain_name(data, offset)
            if offset + 10 > len(data):
                break
            # Saltar tipo, clase, TTL
            offset += 8
            # Obtener longitud de datos y saltarlos
            rdlength = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2 + rdlength
        
        # Parsear sección adicional (para detectar EDNS0)
        edns0_detected = False
        for _ in range(arcount):
            if offset >= len(data):
                break
            
            name_start = offset
            domain, offset = self.parse_domain_name(data, offset)
            
            if offset + 10 > len(data):
                break
                
            rtype = struct.unpack('!H', data[offset:offset+2])[0]
            rclass = struct.unpack('!H', data[offset+2:offset+4])[0]
            ttl = struct.unpack('!I', data[offset+4:offset+8])[0]
            rdlength = struct.unpack('!H', data[offset+8:offset+10])[0]
            
            # Detectar EDNS0 (tipo 41)
            if rtype == 41:
                edns0_detected = True
                additional.append({
                    'type': 'EDNS0',
                    'udp_size': rclass,  # En EDNS0, class field es UDP payload size
                    'extended_rcode': (ttl >> 24) & 0xFF,
                    'version': (ttl >> 16) & 0xFF,
                    'flags': ttl & 0xFFFF
                })
            
            offset += 10 + rdlength
        
        return {
            'header': header,
            'questions': questions,
            'additional': additional,
            'edns0_detected': edns0_detected
        }
    
    def build_response(self, query_data, domain, query_type, query_class, query_flags, edns0_info=None):
        """Construye la respuesta DNS mejorada"""
        if len(query_data) < 12:
            raise ValueError("Query demasiado corta")
        
        # Header de respuesta
        transaction_id = query_data[0:2]
        
        # Flags de respuesta mejorados
        # Preservar RD bit de la query original
        original_flags = struct.unpack('!H', query_data[2:4])[0]
        rd_bit = original_flags & 0x0100  # Recursion Desired
        
        # QR=1 (respuesta), Opcode=0, AA=0 (no autoritativo para ser más compatible),
        # TC=0, RD=preservado, RA=1, Z=0, RCODE=0
        flags = 0x8000 | rd_bit | 0x0080  # QR=1, RA=1, preservar RD
        
        # Construir header completo
        response = bytearray()
        response.extend(transaction_id)                    # Transaction ID
        response.extend(struct.pack('!H', flags))          # Flags
        response.extend(struct.pack('!H', 1))              # Questions = 1
        response.extend(struct.pack('!H', 1))              # Answers = 1
        response.extend(struct.pack('!H', 0))              # Authority RRs = 0
        
        # Additional RRs (1 si hay EDNS0, 0 si no)
        additional_count = 1 if edns0_info else 0
        response.extend(struct.pack('!H', additional_count))
        
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
        response.extend(struct.pack('!I', 300))            # TTL más conservador
        
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
            flags_nxdomain = flags | 0x0003
            response[2:4] = struct.pack('!H', flags_nxdomain)
            response[6:8] = struct.pack('!H', 0)  # Answers = 0
            response[10:12] = struct.pack('!H', 0)  # Additional = 0
            response_value = "NXDOMAIN"
            return bytes(response), response_value
        
        # Agregar sección EDNS0 si fue detectada en la query
        if edns0_info:
            response.extend(b'\x00')                       # Root domain (.)
            response.extend(struct.pack('!H', 41))         # Type OPT (EDNS0)
            response.extend(struct.pack('!H', 4096))       # UDP payload size
            response.extend(struct.pack('!I', 0))          # Extended RCODE, Version, Flags
            response.extend(struct.pack('!H', 0))          # RDLEN = 0 (no options)
        
        return bytes(response), response_value
    
    def handle_query(self, data, addr, sock):
        """Maneja una consulta DNS con mejor compatibilidad"""
        try:
            # Parsear query completa
            query_info = self.parse_query_sections(data)
            
            if not query_info['questions']:
                raise ValueError("No hay preguntas en la query")
            
            # Tomar la primera pregunta
            question = query_info['questions'][0]
            domain = question['domain']
            query_type = question['type']
            query_class = question['class']
            
            # Solo soportar clase IN (Internet)
            if query_class != 1:
                raise ValueError(f"Clase no soportada: {query_class}")
            
            # Mapeo de tipos de consulta para logging
            query_types = {
                1: 'A', 28: 'AAAA', 15: 'MX', 5: 'CNAME', 
                16: 'TXT', 2: 'NS', 6: 'SOA', 12: 'PTR'
            }
            type_name = query_types.get(query_type, f'TYPE{query_type}')
            
            # Log de consulta con información EDNS0
            log_data = {
                "event_type": "query",
                "client_ip": addr[0],
                "client_port": addr[1],
                "domain": domain,
                "query_type": type_name,
                "query_type_code": query_type,
                "query_class": query_class,
                "transaction_id": query_info['header'][0],
                "query_size": len(data),
                "edns0_detected": query_info['edns0_detected']
            }
            
            if query_info['edns0_detected']:
                log_data["edns0_info"] = query_info['additional']
            
            self.log_event(log_data)
            
            # Construir y enviar respuesta
            original_flags = query_info['header'][1]
            edns0_info = query_info['additional'][0] if query_info['edns0_detected'] else None
            
            response, response_value = self.build_response(
                data, domain, query_type, query_class, original_flags, edns0_info
            )
            
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
                "ttl": 300,
                "edns0_included": edns0_info is not None
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
                    # SERVFAIL con flags más compatibles
                    original_flags = struct.unpack('!H', data[2:4])[0]
                    rd_bit = original_flags & 0x0100
                    error_flags = 0x8000 | rd_bit | 0x0080 | 0x0002  # QR=1, RA=1, RCODE=SERVFAIL
                    error_response.extend(struct.pack('!H', error_flags))
                    error_response.extend(data[4:12])  # Contadores originales
                    sock.sendto(bytes(error_response), addr)
            except:
                pass  # Si no se puede enviar error, ignorar
    
    def start(self):
        """Inicia el servidor DNS"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Aumentar buffer para EDNS0
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        
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
        print(f"🔧 Características:")
        print(f"   ✅ Soporte EDNS0")
        print(f"   ✅ Flags compatibles con OpenDNS")
        print(f"   ✅ Manejo mejorado de errores")
        print(f"📝 Archivo de log JSON: {self.log_file}")
        print("=" * 60)
        
        try:
            while True:
                # Aumentar tamaño de buffer para EDNS0
                data, addr = sock.recvfrom(4096)
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
