package sni

// ParseClientHello 从 TLS ClientHello 中取出 SNI 与 ALPN（不解密）
func ParseClientHello(b []byte) (sniStr, alpn string, ok bool) {
	if len(b) < 5 || b[0] != 0x16 {
		return "", "", false
	}
	// record: type(1) ver(2) len(2)
	recLen := int(b[3])<<8 | int(b[4])
	end := 5 + recLen
	if end > len(b) {
		end = len(b)
	}
	p := b[5:end]
	if len(p) < 4 || p[0] != 0x01 { // handshake: client_hello
		return "", "", false
	}

	p = p[4:] // 跳过 handshake type + length(3)
	// client_version(2) + random(32)
	if len(p) < 34 {
		return "", "", false
	}
	p = p[34:]
	// session_id
	if len(p) < 1 {
		return "", "", false
	}
	sidLen := int(p[0])
	if len(p) < 1+sidLen {
		return "", "", false
	}
	p = p[1+sidLen:]
	// cipher_suites
	if len(p) < 2 {
		return "", "", false
	}
	csLen := int(p[0])<<8 | int(p[1])
	if len(p) < 2+csLen {
		return "", "", false
	}
	p = p[2+csLen:]
	// compression_methods
	if len(p) < 1 {
		return "", "", false
	}
	cmLen := int(p[0])
	if len(p) < 1+cmLen {
		return "", "", false
	}
	p = p[1+cmLen:]
	// extensions
	if len(p) < 2 {
		return "", "", false
	}
	extLen := int(p[0])<<8 | int(p[1])
	if len(p) < 2+extLen {
		return "", "", false
	}
	p = p[2 : 2+extLen]

	for len(p) >= 4 {
		typ := int(p[0])<<8 | int(p[1])
		l := int(p[2])<<8 | int(p[3])
		p = p[4:]
		if l > len(p) {
			return "", "", false
		}
		data := p[:l]
		p = p[l:]
		switch typ {
		case 0x0000: // server_name
			if len(data) < 2 {
				continue
			}
			n := int(data[0])<<8 | int(data[1])
			rest := data[2:]
			for len(rest) >= 3 {
				nameType := rest[0]
				nameLen := int(rest[1])<<8 | int(rest[2])
				rest = rest[3:]
				if nameLen > len(rest) {
					break
				}
				if nameType == 0 {
					sniStr = string(rest[:nameLen])
				}
				rest = rest[nameLen:]
				_ = n
			}
		case 0x0010: // ALPN
			if len(data) < 2 {
				continue
			}
			rest := data[2:]
			if len(rest) >= 1 {
				l2 := int(rest[0])
				if 1+l2 <= len(rest) {
					alpn = string(rest[1 : 1+l2])
				}
			}
		}
	}
	if sniStr == "" {
		return "", alpn, false
	}
	return sniStr, alpn, true
}
