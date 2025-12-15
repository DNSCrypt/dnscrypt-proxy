package rdata

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"codeberg.org/miekg/dns/deleg"
	"codeberg.org/miekg/dns/internal/dnsstring"
	"codeberg.org/miekg/dns/pool"
	"codeberg.org/miekg/dns/svcb"
)

var builderPool = &pool.Builder{Pool: sync.Pool{New: func() any { return strings.Builder{} }}}

func (rd RRSIG) String() string {
	sb := builderPool.Get()
	sprintData(&sb, typeToString(rd.TypeCovered),
		strconv.Itoa(int(rd.Algorithm)),
		strconv.Itoa(int(rd.Labels)),
		strconv.FormatInt(int64(rd.OrigTTL), 10),
		dnsutilTimeToString(rd.Expiration),
		dnsutilTimeToString(rd.Inception),
		strconv.Itoa(int(rd.KeyTag)),
		rd.SignerName,
		rd.Signature)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd LOC) String() string {
	sb := builderPool.Get()
	lat := rd.Latitude
	ns := "N"
	if lat > dnsstring.LOCEquator {
		lat = lat - dnsstring.LOCEquator
	} else {
		ns = "S"
		lat = dnsstring.LOCEquator - lat
	}
	h := lat / dnsstring.LOCDegrees
	lat = lat % dnsstring.LOCDegrees
	m := lat / dnsstring.LOCHours
	lat = lat % dnsstring.LOCHours

	sb.WriteString(fmt.Sprintf("%02d %02d %0.3f %s ", h, m, float64(lat)/1000, ns))

	lon := rd.Longitude
	ew := "E"
	if lon > dnsstring.LOCPrimemeridian {
		lon = lon - dnsstring.LOCPrimemeridian
	} else {
		ew = "W"
		lon = dnsstring.LOCPrimemeridian - lon
	}
	h = lon / dnsstring.LOCDegrees
	lon = lon % dnsstring.LOCDegrees
	m = lon / dnsstring.LOCHours
	lon = lon % dnsstring.LOCHours

	sb.WriteString(fmt.Sprintf("%02d %02d %0.3f %s ", h, m, float64(lon)/1000, ew))

	alt := float64(rd.Altitude) / 100
	alt -= dnsstring.LOCAltitudebase
	if rd.Altitude%100 != 0 {
		sb.WriteString(fmt.Sprintf("%.2fm ", alt))
	} else {
		sb.WriteString(fmt.Sprintf("%.0fm ", alt))
	}

	sb.WriteString(cmToM(rd.Size) + "m ")
	sb.WriteString(cmToM(rd.HorizPre) + "m ")
	sb.WriteString(cmToM(rd.VertPre) + "m")
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd CERT) String() string {
	sb := builderPool.Get()
	if certtype, ok := dnsstring.CertTypeToString[rd.Type]; !ok {
		sb.WriteString(strconv.Itoa(int(rd.Type)))
	} else {
		sb.WriteString(certtype)
	}

	sb.WriteByte(' ')
	sb.WriteString(strconv.Itoa(int(rd.KeyTag)))
	sb.WriteByte(' ')

	if algorithm, ok := dnsstring.AlgorithmToString[rd.Algorithm]; ok {
		sb.WriteString(algorithm)
	} else {
		sb.WriteString(strconv.Itoa(int(rd.Algorithm)))
	}
	sb.WriteByte(' ')

	sb.WriteString(rd.Certificate)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd NSEC3) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Hash)),
		strconv.Itoa(int(rd.Flags)),
		strconv.Itoa(int(rd.Iterations)),
		saltToString(rd.Salt),
		rd.NextDomain)
	for _, t := range rd.TypeBitMap {
		sb.WriteByte(' ')
		sb.WriteString(typeToString(t))
	}
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd NSEC3PARAM) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Hash)),
		strconv.Itoa(int(rd.Flags)),
		strconv.Itoa(int(rd.Iterations)),
		saltToString(rd.Salt))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd NULL) String() string  { return rd.Null }
func (rd CNAME) String() string { return rd.Target }
func (rd HINFO) String() string { return sprintTxt([]string{rd.Cpu, rd.Os}) }
func (rd MB) String() string    { return rd.Mb }
func (rd MG) String() string    { return rd.Mg }
func (rd MR) String() string    { return rd.Mr }
func (rd MF) String() string    { return rd.Mf }
func (rd MD) String() string    { return rd.Md }
func (rd X25) String() string   { return rd.PSDNAddress }
func (rd NS) String() string    { return rd.Ns }
func (rd PTR) String() string   { return rd.Ptr }
func (rd EUI48) String() string { return euiToString(rd.Address, 48) }
func (rd EUI64) String() string { return euiToString(rd.Address, 64) }

func (rd MINFO) String() string {
	sb := builderPool.Get()
	sprintData(&sb, rd.Rmail, rd.Email)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd MX) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Preference)), rd.Mx)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd AFSDB) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Subtype)), rd.Hostname)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd ISDN) String() string {
	sb := builderPool.Get()
	sb.WriteString(sprintTxt([]string{rd.Address, rd.SubAddress}))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd RT) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Preference)), rd.Host)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd RP) String() string {
	sb := builderPool.Get()
	sprintData(&sb, rd.Mbox, rd.Txt)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd SOA) String() string {
	sb := builderPool.Get()
	sprintData(&sb, rd.Ns, rd.Mbox,
		strconv.FormatInt(int64(rd.Serial), 10),
		strconv.FormatInt(int64(rd.Refresh), 10),
		strconv.FormatInt(int64(rd.Retry), 10),
		strconv.FormatInt(int64(rd.Expire), 10),
		strconv.FormatInt(int64(rd.Minttl), 10))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd TXT) String() string {
	sb := builderPool.Get()
	sb.WriteString(sprintTxt(rd.Txt))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd IPN) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Node)))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd SRV) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Priority)),
		strconv.Itoa(int(rd.Weight)),
		strconv.Itoa(int(rd.Port)), rd.Target)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd NAPTR) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Order)), strconv.Itoa(int(rd.Preference)))

	sb.WriteByte(' ')
	sb.WriteByte('"')
	sb.WriteString(rd.Flags)
	sb.WriteByte('"')

	sb.WriteByte(' ')
	sb.WriteByte('"')
	sb.WriteString(rd.Service)
	sb.WriteByte('"')

	sb.WriteByte(' ')
	sb.WriteByte('"')
	sb.WriteString(rd.Regexp)
	sb.WriteByte('"')
	sb.WriteByte(' ')

	sb.WriteString(rd.Replacement)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd DNAME) String() string { return rd.Target }

func (rd A) String() string {
	sb := builderPool.Get()
	defer builderPool.Put(sb)
	if !rd.Addr.IsValid() {
		return sb.String()
	}
	sb.WriteString(rd.Addr.String())
	return sb.String()
}

func (rd AAAA) String() string {
	sb := builderPool.Get()
	defer builderPool.Put(sb)
	if !rd.Addr.IsValid() {
		return sb.String()
	}

	sb.WriteString(rd.Addr.String())
	return sb.String()
}

func (rd PX) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Preference)), rd.Map822, rd.Mapx400)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd GPOS) String() string {
	sb := builderPool.Get()
	sprintData(&sb, rd.Longitude, rd.Latitude, rd.Altitude)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd NSEC) String() string {
	sb := builderPool.Get()
	sb.WriteString(rd.NextDomain)
	for _, t := range rd.TypeBitMap {
		sb.WriteByte(' ')
		sb.WriteString(typeToString(t))
	}
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd DS) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.KeyTag)),
		strconv.Itoa(int(rd.Algorithm)),
		strconv.Itoa(int(rd.DigestType)),
		strings.ToUpper(rd.Digest))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd KX) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Preference)), rd.Exchanger)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd TA) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.KeyTag)),
		strconv.Itoa(int(rd.Algorithm)),
		strconv.Itoa(int(rd.DigestType)),
		strings.ToUpper(rd.Digest))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd TALINK) String() string {
	sb := builderPool.Get()
	sprintData(&sb, rd.PreviousName, rd.NextName)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd SSHFP) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Algorithm)),
		strconv.Itoa(int(rd.Type)),
		strings.ToUpper(rd.FingerPrint))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd DNSKEY) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Flags)),
		strconv.Itoa(int(rd.Protocol)),
		strconv.Itoa(int(rd.Algorithm)),
		rd.PublicKey)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd RKEY) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Flags)),
		strconv.Itoa(int(rd.Protocol)),
		strconv.Itoa(int(rd.Algorithm)),
		rd.PublicKey)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd NSAPPTR) String() string { return rd.Ptr }

// TKEY has no official presentation format, but this will suffice.
func (rd TKEY) String() string {
	sb := builderPool.Get()
	sprintData(&sb, rd.Algorithm,
		dnsutilTimeToString(rd.Inception),
		dnsutilTimeToString(rd.Expiration),
		strconv.Itoa(int(rd.Mode)),
		strconv.Itoa(int(rd.Error)),
		strconv.Itoa(int(rd.KeySize)),
		rd.Key,
		strconv.Itoa(int(rd.OtherLen)),
		rd.OtherData)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd RFC3597) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(len(rd.Data)/2), rd.Data)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd URI) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Priority)), strconv.Itoa(int(rd.Weight)), sprintTxt([]string{rd.Target}))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd DHCID) String() string {
	sb := builderPool.Get()
	sb.WriteString(rd.Digest)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd TLSA) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Usage)),
		strconv.Itoa(int(rd.Selector)),
		strconv.Itoa(int(rd.MatchingType)),
		rd.Certificate)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd SMIMEA) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Usage)), strconv.Itoa(int(rd.Selector)), strconv.Itoa(int(rd.MatchingType)))

	// Every Nth char needs a space on this output. If we output
	// this as one giant line, we can't read it can in because in some cases
	// the cert length overflows scan.maxTok (2048).
	sx := splitN(rd.Certificate, 1024) // conservative value here
	sb.WriteByte(' ')
	sb.WriteString(strings.Join(sx, " "))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd HIP) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.PublicKeyAlgorithm)), rd.Hit, rd.PublicKey)
	for _, d := range rd.RendezvousServers {
		sb.WriteByte(' ')
		sb.WriteString(d)
	}
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd NINFO) String() string {
	sb := builderPool.Get()
	sb.WriteString(sprintTxt(rd.ZSData))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd NID) String() string {
	sb := builderPool.Get()
	sb.WriteString(strconv.Itoa(int(rd.Preference)))
	node := fmt.Sprintf("%0.16x", rd.NodeID)
	sb.WriteByte(' ')
	sb.WriteString(node[0:4])
	sb.WriteByte(':')
	sb.WriteString(node[4:8])
	sb.WriteByte(':')
	sb.WriteString(node[8:12])
	sb.WriteByte(':')
	sb.WriteString(node[12:16])
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd L32) String() string {
	sb := builderPool.Get()
	defer builderPool.Put(sb)
	sb.WriteString(strconv.Itoa(int(rd.Preference)))
	if !rd.Locator32.IsValid() {
		return sb.String()
	}
	sb.WriteByte(' ')
	sb.WriteString(rd.Locator32.String())
	return sb.String()
}

func (rd L64) String() string {
	sb := builderPool.Get()
	sb.WriteString(strconv.Itoa(int(rd.Preference)))
	node := fmt.Sprintf("%0.16X", rd.Locator64)
	sb.WriteByte(' ')
	sb.WriteString(node[0:4])
	sb.WriteByte(':')
	sb.WriteString(node[4:8])
	sb.WriteByte(':')
	sb.WriteString(node[8:12])
	sb.WriteByte(':')
	sb.WriteString(node[12:16])
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd LP) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Preference)), rd.Fqdn)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd CAA) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Flag)), rd.Tag, sprintTxt([]string{rd.Value}))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd UID) String() string {
	sb := builderPool.Get()
	sb.WriteString(strconv.FormatInt(int64(rd.Uid), 10))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd GID) String() string {
	sb := builderPool.Get()
	sb.WriteString(strconv.FormatInt(int64(rd.Gid), 10))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd UINFO) String() string {
	sb := builderPool.Get()
	sb.WriteString(sprintTxt([]string{rd.Uinfo}))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd EID) String() string {
	sb := builderPool.Get()
	sb.WriteString(strings.ToUpper(rd.Endpoint))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd NIMLOC) String() string {
	sb := builderPool.Get()
	sb.WriteString(rd.Locator)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd OPENPGPKEY) String() string {
	sb := builderPool.Get()
	sb.WriteString(rd.PublicKey)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd CSYNC) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.FormatInt(int64(rd.Serial), 10), strconv.Itoa(int(rd.Flags)))
	for _, t := range rd.TypeBitMap {
		sb.WriteByte(' ')
		sb.WriteString(typeToString(t))
	}
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd ZONEMD) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Serial)), strconv.Itoa(int(rd.Scheme)), strconv.Itoa(int(rd.Hash)), rd.Digest)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd SVCB) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rd.Priority)), rd.Target)
	for _, p := range rd.Value {
		sb.WriteByte(' ')
		k := svcb.PairToKey(p)
		sb.WriteString(svcb.KeyToString(k))
		sb.WriteByte('=')
		sb.WriteByte('"')
		sb.WriteString(p.String())
		sb.WriteByte('"')
	}
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd DELEG) String() string {
	sb := builderPool.Get()
	for _, i := range rd.Value {
		sb.WriteByte(' ')
		k := deleg.InfoToKey(i)
		sb.WriteString(deleg.KeyToString(k))
		sb.WriteByte('=')
		sb.WriteByte('"')
		sb.WriteString(i.String())
		sb.WriteByte('"')
	}
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd DSYNC) String() string {
	sb := builderPool.Get()
	sb.WriteString(typeToString(rd.Type))
	sb.WriteByte(' ')
	if rd.Scheme == 1 {
		sb.WriteString("NOTIFY")
	} else {
		sb.WriteString(strconv.Itoa(int(rd.Scheme)))
	}
	sb.WriteByte(' ')

	sb.WriteString(strconv.Itoa(int(rd.Port)))
	sb.WriteByte(' ')
	sb.WriteString(rd.Target)

	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rd TSIG) String() string {
	sb := builderPool.Get()
	sprintData(&sb, rd.Algorithm, tsigTimeToString(rd.TimeSigned),
		strconv.Itoa(int(rd.Fudge)), strconv.Itoa(int(rd.MACSize)),
		strings.ToUpper(rd.MAC), strconv.Itoa(int(rd.OrigID)),
		strconv.Itoa(int(rd.Error)), strconv.Itoa(int(rd.OtherLen)), rd.OtherData)
	s := sb.String()
	builderPool.Put(sb)
	return s
}
