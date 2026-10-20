package revera

// This file supplies the LC_CTYPE and ERE-relevant LC_COLLATE operations that the engine needs.
// It does not read the host locale database.
// The data comes from CLDR 48.2 and covers all 1,122 CLDR locales plus the POSIX locale.
//
// The caller hands the data blob to LocaleOpen as a string.
// A Locale value keeps that string and a parsed section table.
// Every lookup therefore reads fixed-width little-endian fields in place and allocates nothing.

// The twelve standard LC_CTYPE classes, in mask bit order.
const (
	classAlnum  uint8 = 0
	classAlpha  uint8 = 1
	classBlank  uint8 = 2
	classCntrl  uint8 = 3
	classDigit  uint8 = 4
	classGraph  uint8 = 5
	classLower  uint8 = 6
	classPrint  uint8 = 7
	classPunct  uint8 = 8
	classSpace  uint8 = 9
	classUpper  uint8 = 10
	classXdigit uint8 = 11
	numClasses        = 12
)

// firstSequenceID is the element ID of the first multi-character collating element.
// Smaller IDs are Unicode scalar values.
const firstSequenceID = 0x110000

// Section indexes match the generator's layout order.
const (
	secCtypeStage1        = 0
	secCtypeBlocks        = 1
	secCaseDefault        = 2
	secCaseTurkic         = 3
	secSeqCodepoints      = 4
	secSequences          = 5
	secRootContractions   = 6
	secRootEquivalences   = 7
	secCollationOverrides = 8
	secContractionAdds    = 9
	secContractionRemoves = 10
	secCollationProfiles  = 11
	secTypeNames          = 12
	secTypeNameOffsets    = 13
	secLocaleNames        = 14
	secLocaleNameOffsets  = 15
	secLocales            = 16
	secLocaleTypes        = 17
	secInvUpperDefault    = 18
	secInvLowerDefault    = 19
	secInvUpperTurkic     = 20
	secInvLowerTurkic     = 21
	secScalars            = 22
	numSections           = 23
)

// SecRange is one section's byte range inside the blob.
type SecRange struct {
	Off int
	End int
}

// Locale identifies one opened locale and collation selection.
// It also carries the data it reads from, which never changes.
// The zero value is not valid, so use LocalePOSIX or LocaleOpen.
type Locale struct {
	blob   string
	sec    [numSections]SecRange
	maxSeq int
	// preimagesDefault and preimagesTurkic bound the case preimages of one scalar under each case profile.
	// The resource contract prices ICase tests with them.
	preimagesDefault int
	preimagesTurkic  int
	collationProfile uint16
	caseProfile      uint8
	posix            bool
	valid            bool
}

// LocalePOSIX returns the POSIX locale, also known as the C locale.
// It needs no data blob.
func LocalePOSIX() Locale {
	var l Locale
	l.maxSeq = 1
	l.preimagesDefault = 1
	l.preimagesTurkic = 1
	l.posix = true
	l.valid = true
	return l
}

// LocaleValid reports whether this locale came from a successful LocalePOSIX or LocaleOpen.
func LocaleValid(l *Locale) bool {
	return l.valid
}

func u32Raw(blob string, off int) uint32 {
	return uint32(blob[off]) | uint32(blob[off+1])<<8 |
		uint32(blob[off+2])<<16 | uint32(blob[off+3])<<24
}

func u16At(l *Locale, sec int, index int) uint16 {
	off := l.sec[sec].Off + 2*index
	return uint16(l.blob[off]) | uint16(l.blob[off+1])<<8
}

func u32At(l *Locale, sec int, index int) uint32 {
	return u32Raw(l.blob, l.sec[sec].Off+4*index)
}

func sectionLen(l *Locale, sec int) int {
	return l.sec[sec].End - l.sec[sec].Off
}

// byteString returns the NUL-terminated string at off inside a name pool section.
func byteString(l *Locale, sec int, off int) string {
	start := l.sec[sec].Off + off
	end := start
	for end < l.sec[sec].End && l.blob[end] != 0 {
		end++
	}
	return l.blob[start:end]
}

// localeLoad parses the blob header and section table into l.
// It reports false on a malformed blob.
func localeLoad(l *Locale, blob string) bool {
	magic := "RVLOC001"
	if len(blob) < len(magic) || blob[0:len(magic)] != magic {
		return false
	}
	l.blob = blob
	cursor := len(magic)
	for i := 0; i < numSections; i++ {
		if len(blob)-cursor < 4 {
			return false
		}
		raw := u32Raw(blob, cursor)
		cursor += 4
		if uint64(raw) > uint64(len(blob)-cursor) {
			return false
		}
		length := int(raw)
		l.sec[i].Off = cursor
		l.sec[i].End = cursor + length
		cursor += length
	}
	if cursor != len(blob) {
		return false
	}
	if sectionLen(l, secScalars) < 4 {
		return false
	}
	l.maxSeq = int(u32At(l, secScalars, 0))
	if l.maxSeq < 1 || l.maxSeq > maxElemAhead {
		// The engine sizes its lookahead buffers with maxElemAhead.
		// It cannot use data with longer collating elements.
		return false
	}
	if !localeValidate(l) {
		return false
	}
	l.preimagesDefault = maxPairRun(l, secInvUpperDefault) +
		maxPairRun(l, secInvLowerDefault)
	l.preimagesTurkic = maxPairRun(l, secInvUpperTurkic) +
		maxPairRun(l, secInvLowerTurkic)
	if l.preimagesDefault > maxPreimages || l.preimagesTurkic > maxPreimages {
		// The fixed preimage buffer must cover every scalar.
		return false
	}
	return true
}

// ctypeStage1Entries is the first-stage table size.
// It holds one entry per possible value of r >> 8 for a Unicode scalar r.
const ctypeStage1Entries = 0x1100

// localeValidate checks every cross-section reference in the blob, so no later lookup can read outside its section.
// The loader rejects a blob that fails any check as malformed.
func localeValidate(l *Locale) bool {
	if sectionLen(l, secCtypeStage1) < 2*ctypeStage1Entries {
		return false
	}
	blocksLen := sectionLen(l, secCtypeBlocks)
	for i := 0; i < ctypeStage1Entries; i++ {
		block := int(u16At(l, secCtypeStage1, i))
		if 2*256*(block+1) > blocksLen {
			return false
		}
	}
	if sectionLen(l, secCaseDefault)%12 != 0 ||
		sectionLen(l, secCaseTurkic)%12 != 0 {
		return false
	}
	if !scalarSectionValid(l, secCaseDefault) || !scalarSectionValid(l, secCaseTurkic) {
		return false
	}
	if sectionLen(l, secInvUpperDefault)%8 != 0 ||
		sectionLen(l, secInvLowerDefault)%8 != 0 ||
		sectionLen(l, secInvUpperTurkic)%8 != 0 ||
		sectionLen(l, secInvLowerTurkic)%8 != 0 {
		return false
	}
	if !scalarSectionValid(l, secInvUpperDefault) || !scalarSectionValid(l, secInvLowerDefault) ||
		!scalarSectionValid(l, secInvUpperTurkic) || !scalarSectionValid(l, secInvLowerTurkic) {
		return false
	}
	if sectionLen(l, secSeqCodepoints)%4 != 0 ||
		sectionLen(l, secSequences)%8 != 0 {
		return false
	}
	if !scalarSectionValid(l, secSeqCodepoints) {
		return false
	}
	codepointCount := sectionLen(l, secSeqCodepoints) / 4
	seqCount := sectionLen(l, secSequences) / 8
	for i := 0; i < seqCount; i++ {
		off := u32At(l, secSequences, 2*i)
		length := u32At(l, secSequences, 2*i+1)
		if length < 1 || length > uint32(l.maxSeq) || !u32SpanWithin(off, length, codepointCount) {
			return false
		}
	}
	if sectionLen(l, secRootContractions)%4 != 0 ||
		sectionLen(l, secContractionAdds)%4 != 0 ||
		sectionLen(l, secContractionRemoves)%4 != 0 ||
		sectionLen(l, secRootEquivalences)%8 != 0 ||
		sectionLen(l, secCollationOverrides)%8 != 0 {
		return false
	}
	// Every contraction ID must name a real sequence row, because the shortest-equivalent search reads that row.
	if !contractionIDsValid(l, secRootContractions, seqCount) {
		return false
	}
	if !contractionIDsValid(l, secContractionAdds, seqCount) {
		return false
	}
	if sectionLen(l, secCollationProfiles)%24 != 0 {
		return false
	}
	profileCount := sectionLen(l, secCollationProfiles) / 24
	// Profile indexes are stored in 16 bits.
	if profileCount > 1<<16 {
		return false
	}
	overrideCount := sectionLen(l, secCollationOverrides) / 8
	addCount := sectionLen(l, secContractionAdds) / 4
	removeCount := sectionLen(l, secContractionRemoves) / 4
	for i := 0; i < profileCount; i++ {
		row := collationProfileRow(l, i)
		if !u32SpanWithin(row.OverrideFirst, row.OverrideCount, overrideCount) ||
			!u32SpanWithin(row.AddFirst, row.AddCount, addCount) ||
			!u32SpanWithin(row.RemoveFirst, row.RemoveCount, removeCount) {
			return false
		}
	}
	if sectionLen(l, secTypeNameOffsets)%4 != 0 {
		return false
	}
	typeNameCount := sectionLen(l, secTypeNameOffsets) / 4
	for i := 0; i < typeNameCount; i++ {
		if !u32Below(u32At(l, secTypeNameOffsets, i), sectionLen(l, secTypeNames)) {
			return false
		}
	}
	if sectionLen(l, secLocales)%20 != 0 ||
		sectionLen(l, secLocaleNameOffsets)%4 != 0 ||
		sectionLen(l, secLocaleTypes)%4 != 0 {
		return false
	}
	count := localesCount(l)
	if sectionLen(l, secLocaleNameOffsets)/4 != count {
		return false
	}
	for i := 0; i < count; i++ {
		if !u32Below(u32At(l, secLocaleNameOffsets, i), sectionLen(l, secLocaleNames)) {
			return false
		}
	}
	typeRowCount := sectionLen(l, secLocaleTypes) / 4
	for i := 0; i < count; i++ {
		row := localeRowAt(l, i)
		if !u32SpanWithin(row.TypeFirst, row.TypeCount, typeRowCount) ||
			row.CaseProfile > 1 ||
			!u32Below(row.DefaultCollation, profileCount) {
			return false
		}
	}
	for i := 0; i < typeRowCount; i++ {
		if int(u16At(l, secLocaleTypes, 2*i+1)) >= profileCount {
			return false
		}
	}
	return true
}

// scalarSectionValid rejects non-scalars in case and sequence data.
func scalarSectionValid(l *Locale, sec int) bool {
	for i := 0; i < sectionLen(l, sec)/4; i++ {
		if !validScalar(int32(u32At(l, sec, i))) {
			return false
		}
	}
	return true
}

// contractionIDsValid checks that every multi-character element ID in a contraction section points at a sequence row.
func contractionIDsValid(l *Locale, sec int, seqCount int) bool {
	count := sectionLen(l, sec) / 4
	for i := 0; i < count; i++ {
		id := u32At(l, sec, i)
		if id >= firstSequenceID && !u32Below(id-firstSequenceID, seqCount) {
			return false
		}
	}
	return true
}

// u32Below and u32SpanWithin check blob fields before they become ints.
// On a 32-bit platform, converting first could turn a large value negative.
func u32Below(v uint32, limit int) bool {
	return uint64(v) < uint64(limit)
}

func u32SpanWithin(first uint32, count uint32, limit int) bool {
	return uint64(first)+uint64(count) <= uint64(limit)
}

// localeMaxElementLength returns the largest character count of any multi-character collating element in the data.
func localeMaxElementLength(l *Locale) int {
	return l.maxSeq
}

func validScalar(r int32) bool {
	return r >= 0 && r <= 0x10ffff && !(r >= 0xd800 && r <= 0xdfff)
}

func asciiLower(c uint8) uint8 {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

const normalizedNameMax = 127

// normalizeName lowercases an ASCII locale name and maps '_' to '-'.
// It stops before an optional codeset or modifier.
// It also checks the codeset when the name carries one.
func normalizeName(input string) (string, bool) {
	if len(input) == 0 {
		return "", false
	}
	out := make([]uint8, 0, len(input))
	i := 0
	for i < len(input) && input[i] != '.' && input[i] != '@' {
		c := input[i]
		if c >= 0x80 || len(out) == normalizedNameMax {
			return "", false
		}
		if c == '_' {
			c = '-'
		} else {
			c = asciiLower(c)
		}
		out = append(out, c)
		i++
	}
	if i < len(input) && input[i] == '.' {
		i++
		codeset := make([]uint8, 0, 5)
		for i < len(input) && input[i] != '@' {
			c := asciiLower(input[i])
			i++
			if len(codeset) == 5 || c >= 0x80 {
				return "", false
			}
			codeset = append(codeset, c)
		}
		if string(codeset) != "utf8" && string(codeset) != "utf-8" {
			return "", false
		}
	}
	return string(out), true
}

// embeddedModifier extracts the value of a @collation= modifier, if the name has one.
func embeddedModifier(name string) (string, bool) {
	at := indexOfByte(name, '@')
	if at < 0 {
		return "", false
	}
	modifier := name[at+1:]
	keyword := "collation="
	if len(modifier) <= len(keyword) {
		return "", false
	}
	for i := 0; i < len(keyword); i++ {
		if asciiLower(modifier[i]) != keyword[i] {
			return "", false
		}
	}
	return modifier[len(keyword):], true
}

func longTypeAlias(name string) string {
	if name == "dict" {
		return "dictionary"
	}
	if name == "phonebk" {
		return "phonebook"
	}
	if name == "trad" {
		return "traditional"
	}
	return name
}

func normalizeType(input string) (string, bool) {
	if len(input) == 0 {
		return "", true
	}
	out := make([]uint8, 0, len(input))
	for i := 0; i < len(input); i++ {
		c := input[i]
		if c >= 0x80 || len(out) == normalizedNameMax {
			return "", false
		}
		out = append(out, asciiLower(c))
	}
	return longTypeAlias(string(out)), true
}

// findName does a binary search over a NUL-separated sorted name pool.
func findName(l *Locale, name string, poolSec int, offsetsSec int, count int) int {
	low := 0
	high := count
	for low < high {
		middle := low + (high-low)/2
		entry := byteString(l, poolSec, int(u32At(l, offsetsSec, middle)))
		if name == entry {
			return middle
		}
		if name < entry {
			high = middle
		} else {
			low = middle + 1
		}
	}
	return -1
}

func localesCount(l *Locale) int {
	return sectionLen(l, secLocales) / 20
}

// LocaleRow mirrors one row of the locales section.
// The row on disk holds five u32 values: name_id, type_first, type_count, case_profile and default_collation.
// Nothing needs name_id after the name search, so this type omits it.
type LocaleRow struct {
	TypeFirst        uint32
	TypeCount        uint32
	CaseProfile      uint32
	DefaultCollation uint32
}

func localeRowAt(l *Locale, index int) LocaleRow {
	base := 5 * index
	var row LocaleRow
	row.TypeFirst = u32At(l, secLocales, base+1)
	row.TypeCount = u32At(l, secLocales, base+2)
	row.CaseProfile = u32At(l, secLocales, base+3)
	row.DefaultCollation = u32At(l, secLocales, base+4)
	return row
}

// localeRequest is one normalized open request.
type localeRequest struct {
	name  string
	ctype string
	posix bool
}

// normalizeRequest resolves the name, the embedded modifier, and the collation type of one open request.
func normalizeRequest(name string, collationType string) (localeRequest, bool) {
	var req localeRequest
	normalized, ok := normalizeName(name)
	if !ok {
		return req, false
	}
	modifier, hasModifier := embeddedModifier(name)
	if indexOfByte(name, '@') >= 0 && !hasModifier {
		return req, false
	}
	if hasModifier && len(collationType) != 0 {
		return req, false
	}
	if hasModifier {
		collationType = modifier
	}
	normalizedType, ok2 := normalizeType(collationType)
	if !ok2 {
		return req, false
	}
	req.name = normalized
	req.ctype = normalizedType
	req.posix = normalized == "c" || normalized == "posix"
	return req, true
}

// posixSelect answers a request that named the POSIX locale.
func posixSelect(ctype string) (Locale, bool) {
	if len(ctype) != 0 && ctype != "standard" {
		var invalid Locale
		return invalid, false
	}
	return LocalePOSIX(), true
}

// LocaleLoad parses and checks a data blob once.
// The result carries the data only and does not work on its own.
// Pass it to LocaleSelect to resolve names against it.
func LocaleLoad(blob string) (Locale, bool) {
	var data Locale
	if !localeLoad(&data, blob) {
		var invalid Locale
		return invalid, false
	}
	return data, true
}

// resolveLocale finds one CLDR locale row and collation profile in loaded data.
func resolveLocale(data *Locale, req localeRequest) (Locale, bool) {
	var invalid Locale
	var result Locale
	result.blob = data.blob
	result.sec = data.sec
	result.maxSeq = data.maxSeq
	result.preimagesDefault = data.preimagesDefault
	result.preimagesTurkic = data.preimagesTurkic
	index := findName(&result, req.name, secLocaleNames,
		secLocaleNameOffsets, localesCount(&result))
	if index < 0 {
		return invalid, false
	}
	row := localeRowAt(&result, index)
	result.caseProfile = uint8(row.CaseProfile)
	result.valid = true
	if len(req.ctype) == 0 {
		result.collationProfile = uint16(row.DefaultCollation)
		return result, true
	}

	typeNameCount := sectionLen(&result, secTypeNameOffsets) / 4
	typeID := findName(&result, req.ctype, secTypeNames,
		secTypeNameOffsets, typeNameCount)
	if typeID < 0 {
		return invalid, false
	}
	low := int(row.TypeFirst)
	high := low + int(row.TypeCount)
	for low < high {
		middle := low + (high-low)/2
		rowTypeID := int(u16At(&result, secLocaleTypes, 2*middle))
		if rowTypeID == typeID {
			result.collationProfile = u16At(&result, secLocaleTypes, 2*middle+1)
			return result, true
		}
		if rowTypeID > typeID {
			high = middle
		} else {
			low = middle + 1
		}
	}
	return invalid, false
}

// LocaleSelect resolves a locale name and optional collation type against data from LocaleLoad.
// Locale names are ASCII case-insensitive.
// They accept '-' or '_' separators, an optional .UTF-8 suffix, and an optional @collation=TYPE modifier.
// C and POSIX select the POSIX locale.
// The result is invalid when the name is unknown.
func LocaleSelect(data *Locale, name string, collationType string) (Locale, bool) {
	req, ok := normalizeRequest(name, collationType)
	if !ok {
		var invalid Locale
		return invalid, false
	}
	if req.posix {
		return posixSelect(req.ctype)
	}
	return resolveLocale(data, req)
}

// LocaleOpen loads a data blob and resolves one locale name in a single step, under the LocaleSelect rules.
// A caller that opens several locales from the same blob loads it once with LocaleLoad.
// It then selects from the result.
func LocaleOpen(blob string, name string, collationType string) (Locale, bool) {
	var invalid Locale
	req, ok := normalizeRequest(name, collationType)
	if !ok {
		return invalid, false
	}
	if req.posix {
		return posixSelect(req.ctype)
	}
	data, ok2 := LocaleLoad(blob)
	if !ok2 {
		return invalid, false
	}
	return resolveLocale(&data, req)
}

// classNames lists the standard class names in class value order.
var classNames = [numClasses]string{
	"alnum", "alpha", "blank", "cntrl", "digit", "graph",
	"lower", "print", "punct", "space", "upper", "xdigit",
}

// classByName maps a standard class name to its identifier.
func classByName(name string) (uint8, bool) {
	for i := 0; i < numClasses; i++ {
		if classNames[i] == name {
			return uint8(i), true
		}
	}
	return 0, false
}

func posixMask(r int32) uint16 {
	upper := r >= 'A' && r <= 'Z'
	lower := r >= 'a' && r <= 'z'
	alpha := upper || lower
	digit := r >= '0' && r <= '9'
	alnum := alpha || digit
	blank := r == ' ' || r == '\t'
	space := blank || r == '\n' || r == '\v' || r == '\f' || r == '\r'
	cntrl := r <= 0x1f || r == 0x7f
	print := r >= 0x20 && r <= 0x7e
	graph := r >= 0x21 && r <= 0x7e
	punct := graph && !alnum
	xdigit := digit || (r >= 'A' && r <= 'F') || (r >= 'a' && r <= 'f')
	var mask uint16
	if alnum {
		mask |= 1 << classAlnum
	}
	if alpha {
		mask |= 1 << classAlpha
	}
	if blank {
		mask |= 1 << classBlank
	}
	if cntrl {
		mask |= 1 << classCntrl
	}
	if digit {
		mask |= 1 << classDigit
	}
	if graph {
		mask |= 1 << classGraph
	}
	if lower {
		mask |= 1 << classLower
	}
	if print {
		mask |= 1 << classPrint
	}
	if punct {
		mask |= 1 << classPunct
	}
	if space {
		mask |= 1 << classSpace
	}
	if upper {
		mask |= 1 << classUpper
	}
	if xdigit {
		mask |= 1 << classXdigit
	}
	return mask
}

// localeClassMask returns the set of standard LC_CTYPE classes that contain r, one bit per class value.
func localeClassMask(l *Locale, r int32) uint16 {
	if !l.valid || !validScalar(r) {
		return 0
	}
	if l.posix {
		return posixMask(r)
	}
	block := int(u16At(l, secCtypeStage1, int(r>>8)))
	return u16At(l, secCtypeBlocks, block*256+int(r&0xff))
}

// CasePair is one case-map row: the uppercase and lowercase counterparts of one scalar.
type CasePair struct {
	Upper int32
	Lower int32
}

// findCase does a binary search in a case-map section of u32 triples.
func findCase(l *Locale, sec int, r int32) (CasePair, bool) {
	var pair CasePair
	count := sectionLen(l, sec) / 12
	low := 0
	high := count
	for low < high {
		middle := low + (high-low)/2
		cp := int32(u32At(l, sec, 3*middle))
		if cp == r {
			pair.Upper = int32(u32At(l, sec, 3*middle+1))
			pair.Lower = int32(u32At(l, sec, 3*middle+2))
			return pair, true
		}
		if cp > r {
			high = middle
		} else {
			low = middle + 1
		}
	}
	return pair, false
}

func caseConvert(l *Locale, r int32, toUpper bool) int32 {
	if !l.valid || !validScalar(r) {
		return r
	}
	if l.posix {
		if toUpper && r >= 'a' && r <= 'z' {
			return r - 32
		}
		if !toUpper && r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return r
	}
	if l.caseProfile == 1 {
		pair, ok := findCase(l, secCaseTurkic, r)
		if ok {
			if toUpper {
				return pair.Upper
			}
			return pair.Lower
		}
	}
	pair, ok := findCase(l, secCaseDefault, r)
	if !ok {
		return r
	}
	if toUpper {
		return pair.Upper
	}
	return pair.Lower
}

// maxPreimages caps how many case preimages one scalar can have.
// localeLoad checks that the data never passes it, so the fixed preimage buffer can never overflow.
const maxPreimages = 16

// preimageBuf collects the case preimages of one scalar without an allocation.
type preimageBuf struct {
	r [maxPreimages]int32
	n int
}

// pairSourcesRun finds the run of sources whose pair target equals r, and copies it into buf.
// The section holds sorted (target, source) u32 pairs.
func pairSourcesRun(l *Locale, buf *preimageBuf, sec int, r int32) {
	count := sectionLen(l, sec) / 8
	low := 0
	high := count
	for low < high {
		middle := low + (high-low)/2
		if int32(u32At(l, sec, 2*middle)) < r {
			low = middle + 1
		} else {
			high = middle
		}
	}
	for low < count {
		if int32(u32At(l, sec, 2*low)) != r {
			break
		}
		buf.r[buf.n] = int32(u32At(l, sec, 2*low+1))
		buf.n++
		low++
	}
}

// maxPairRun returns the longest run of equal targets in one (target, source) pair section.
func maxPairRun(l *Locale, sec int) int {
	count := sectionLen(l, sec) / 8
	longest := 0
	run := 0
	var last uint32
	for i := 0; i < count; i++ {
		target := u32At(l, sec, 2*i)
		if i > 0 && target == last {
			run++
		} else {
			run = 1
			last = target
		}
		longest = max(longest, run)
	}
	return longest
}

// localeMaxPreimages returns the most case preimages one scalar can have under the locale's case profile.
func localeMaxPreimages(l *Locale) int {
	if l.caseProfile == 1 {
		return l.preimagesTurkic
	}
	return l.preimagesDefault
}

// localeCasePreimages fills buf with every scalar, other than r itself, whose uppercase or lowercase counterpart is r.
// The REG_ICASE closure rule needs these preimages.
// A subject character matches when some accepted character maps to it, and case mappings are not always involutions.
func localeCasePreimages(l *Locale, buf *preimageBuf, r int32) {
	buf.n = 0
	if !l.valid || !validScalar(r) {
		return
	}
	if l.posix {
		if r >= 'A' && r <= 'Z' {
			buf.r[0] = r + 32
			buf.n = 1
		}
		if r >= 'a' && r <= 'z' {
			buf.r[0] = r - 32
			buf.n = 1
		}
		return
	}
	upperSec := secInvUpperDefault
	lowerSec := secInvLowerDefault
	if l.caseProfile == 1 {
		upperSec = secInvUpperTurkic
		lowerSec = secInvLowerTurkic
	}
	pairSourcesRun(l, buf, upperSec, r)
	pairSourcesRun(l, buf, lowerSec, r)
	// Drop duplicates and r itself.
	// The runs are tiny.
	w := 0
	for i := 0; i < buf.n; i++ {
		candidate := buf.r[i]
		if candidate != r && !runesContain(buf.r[0:w], candidate) {
			buf.r[w] = candidate
			w++
		}
	}
	buf.n = w
}

// localeToUpper returns the locale's one-character uppercase counterpart, or the input itself.
func localeToUpper(l *Locale, r int32) int32 {
	return caseConvert(l, r, true)
}

// localeToLower returns the locale's one-character lowercase counterpart, or the input itself.
func localeToLower(l *Locale, r int32) int32 {
	return caseConvert(l, r, false)
}

// compareSequence orders a scalar sequence against a stored sequence index.
func compareSequence(l *Locale, seq []int32, index int) int {
	off := int(u32At(l, secSequences, 2*index))
	length := int(u32At(l, secSequences, 2*index+1))
	common := min(length, len(seq))
	for i := 0; i < common; i++ {
		stored := int32(u32At(l, secSeqCodepoints, off+i))
		if seq[i] < stored {
			return -1
		}
		if seq[i] > stored {
			return 1
		}
	}
	if len(seq) < length {
		return -1
	}
	if len(seq) > length {
		return 1
	}
	return 0
}

// elementID maps a scalar sequence to its collating-element ID.
// A single scalar maps to itself.
// A known multi-scalar sequence maps to firstSequenceID plus its table index.
func elementID(l *Locale, seq []int32) (uint32, bool) {
	if len(seq) == 0 {
		return 0, false
	}
	for i := 0; i < len(seq); i++ {
		if !validScalar(seq[i]) {
			return 0, false
		}
	}
	if len(seq) == 1 {
		return uint32(seq[0]), true
	}
	count := sectionLen(l, secSequences) / 8
	low := 0
	high := count
	for low < high {
		middle := low + (high-low)/2
		comparison := compareSequence(l, seq, middle)
		if comparison == 0 {
			return uint32(firstSequenceID + middle), true
		}
		if comparison < 0 {
			high = middle
		} else {
			low = middle + 1
		}
	}
	return 0, false
}

// u32Contains does a binary search in a slice of a sorted u32 section.
func u32Contains(l *Locale, sec int, first int, count int, needle uint32) bool {
	low := first
	high := first + count
	for low < high {
		middle := low + (high-low)/2
		value := u32At(l, sec, middle)
		if value == needle {
			return true
		}
		if value > needle {
			high = middle
		} else {
			low = middle + 1
		}
	}
	return false
}

// CollProfile mirrors one row of the collation profiles section.
type CollProfile struct {
	OverrideFirst uint32
	OverrideCount uint32
	AddFirst      uint32
	AddCount      uint32
	RemoveFirst   uint32
	RemoveCount   uint32
}

func collationProfileRow(l *Locale, index int) CollProfile {
	base := 6 * index
	var row CollProfile
	row.OverrideFirst = u32At(l, secCollationProfiles, base)
	row.OverrideCount = u32At(l, secCollationProfiles, base+1)
	row.AddFirst = u32At(l, secCollationProfiles, base+2)
	row.AddCount = u32At(l, secCollationProfiles, base+3)
	row.RemoveFirst = u32At(l, secCollationProfiles, base+4)
	row.RemoveCount = u32At(l, secCollationProfiles, base+5)
	return row
}

func isContraction(l *Locale, element uint32) bool {
	if l.posix {
		return false
	}
	row := collationProfileRow(l, int(l.collationProfile))
	if u32Contains(l, secContractionAdds, int(row.AddFirst), int(row.AddCount), element) {
		return true
	}
	rootCount := sectionLen(l, secRootContractions) / 4
	if !u32Contains(l, secRootContractions, 0, rootCount, element) {
		return false
	}
	return !u32Contains(l, secContractionRemoves, int(row.RemoveFirst),
		int(row.RemoveCount), element)
}

// collatingElementID maps seq to its element ID when seq is one collating element in this locale.
func collatingElementID(l *Locale, seq []int32) (uint32, bool) {
	element, ok := elementID(l, seq)
	if !ok {
		return 0, false
	}
	if len(seq) > 1 && !isContraction(l, element) {
		return 0, false
	}
	return element, true
}

// localeIsCollatingElement tests whether a scalar sequence is one collating element in this locale.
func localeIsCollatingElement(l *Locale, seq []int32) bool {
	if !l.valid {
		return false
	}
	_, ok := collatingElementID(l, seq)
	return ok
}

// LocaleCollatingPrefix returns the length in scalars of the longest collating-element prefix of seq.
// It returns zero for invalid input.
func LocaleCollatingPrefix(l *Locale, seq []int32) int {
	if !l.valid || len(seq) == 0 {
		return 0
	}
	maximum := min(len(seq), l.maxSeq)
	for candidate := maximum; candidate >= 2; candidate-- {
		if localeIsCollatingElement(l, seq[0:candidate]) {
			return candidate
		}
	}
	if localeIsCollatingElement(l, seq[0:1]) {
		return 1
	}
	return 0
}

// findPair does a binary search in a section of sorted (element, representative) u32 pairs.
func findPair(l *Locale, sec int, first int, count int, element uint32) (uint32, bool) {
	low := first
	high := first + count
	for low < high {
		middle := low + (high-low)/2
		key := u32At(l, sec, 2*middle)
		if key == element {
			return u32At(l, sec, 2*middle+1), true
		}
		if key > element {
			high = middle
		} else {
			low = middle + 1
		}
	}
	return 0, false
}

func primaryToken(l *Locale, element uint32) uint64 {
	row := collationProfileRow(l, int(l.collationProfile))
	rep, ok := findPair(l, secCollationOverrides, int(row.OverrideFirst),
		int(row.OverrideCount), element)
	if ok {
		return 0x2_0000_0000 | uint64(rep)
	}
	rootCount := sectionLen(l, secRootEquivalences) / 8
	rep, ok = findPair(l, secRootEquivalences, 0, rootCount, element)
	if ok {
		return 0x1_0000_0000 | uint64(rep)
	}
	return uint64(element)
}

// localePrimaryEqual tests primary LC_COLLATE equivalence between two collating elements.
func localePrimaryEqual(l *Locale, left []int32, right []int32) bool {
	if !l.valid {
		return false
	}
	leftElement, ok := collatingElementID(l, left)
	if !ok {
		return false
	}
	rightElement, ok2 := collatingElementID(l, right)
	if !ok2 {
		return false
	}
	if leftElement == rightElement {
		return true
	}
	if l.posix {
		return false
	}
	return primaryToken(l, leftElement) == primaryToken(l, rightElement)
}

// localeMinEquivLength returns the smallest scalar count of any collating element whose primary weight equals the element seq in this locale.
// The bracket compiler uses it as the minimum length of an equivalence-class match.
func localeMinEquivLength(l *Locale, seq []int32) int {
	if !l.valid {
		return len(seq)
	}
	element, ok := collatingElementID(l, seq)
	if !ok {
		return len(seq)
	}
	if element < firstSequenceID {
		return 1
	}
	if l.posix {
		return len(seq)
	}
	// Every element that is not seq itself and shares its primary weight appears in the equivalence pair sections.
	// An unlisted element keeps its own ID as its token, which cannot collide.
	token := primaryToken(l, element)
	best := len(seq)
	row := collationProfileRow(l, int(l.collationProfile))
	best = minTokenLength(l, secCollationOverrides, int(row.OverrideFirst),
		int(row.OverrideCount), token, best)
	if best == 1 {
		return 1
	}
	rootCount := sectionLen(l, secRootEquivalences) / 8
	return minTokenLength(l, secRootEquivalences, 0, rootCount, token, best)
}

// minTokenLength scans one (element, representative) pair section.
// It lowers best to the shortest collating element with the given token.
func minTokenLength(l *Locale, sec int, first int, count int, token uint64, best int) int {
	for i := first; i < first+count; i++ {
		candidate := u32At(l, sec, 2*i)
		if primaryToken(l, candidate) != token {
			continue
		}
		if candidate < firstSequenceID {
			return 1
		}
		if !isContraction(l, candidate) {
			continue
		}
		index := int(candidate - firstSequenceID)
		best = min(best, int(u32At(l, secSequences, 2*index+1)))
	}
	return best
}

// localeSupportsRanges reports whether bracket ranges are defined in this locale.
// Ranges in a non-POSIX locale use the permitted reject policy on purpose.
func localeSupportsRanges(l *Locale) bool {
	return l.valid && l.posix
}

// LocaleCount returns the CLDR locale count in the blob, without the C and POSIX aliases.
func LocaleCount(l *Locale) int {
	return localesCount(l)
}

// LocaleName returns the normalized CLDR name at index, or "" when the index is out of range.
func LocaleName(l *Locale, index int) string {
	if index < 0 || index >= localesCount(l) {
		return ""
	}
	return byteString(l, secLocaleNames, int(u32At(l, secLocaleNameOffsets, index)))
}
