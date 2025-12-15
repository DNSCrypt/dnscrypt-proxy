package dns

import "codeberg.org/miekg/dns/internal/reverse"

// StringToType is the reverse of [TypeToString].
var StringToType = reverse.Int16(TypeToString)

// StringToCode is the reverse of [CodeToString].
var StringToCode = reverse.Int16(CodeToString)

// StringToClass is the reverse of [ClassToString].
var StringToClass = reverse.Int16(ClassToString)

// StringToOpcode is a map of opcodes to strings.
var StringToOpcode = reverse.Int8(OpcodeToString)

// StringToRcode is a map of rcodes to strings.
var StringToRcode = reverse.Int16(RcodeToString)

// StringToAlgorithm is the reverse of [AlgorithmToString].
var StringToAlgorithm = reverse.Int8(AlgorithmToString)

// StringToHash is a map of names to hash IDs.
var StringToHash = reverse.Int8(HashToString)

// StringToCertType is the reverse of [CertTypeToString].
var StringToCertType = reverse.Int16(CertTypeToString)
