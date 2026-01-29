package dns

import "codeberg.org/miekg/dns/internal/reverse"

// StringToType is the reverse of [TypeToString].
var StringToType = reverse.Map(TypeToString)

// StringToCode is the reverse of [CodeToString].
var StringToCode = reverse.Map(CodeToString)

// StringToClass is the reverse of [ClassToString].
var StringToClass = reverse.Map(ClassToString)

// StringToOpcode is a map of opcodes to strings.
var StringToOpcode = reverse.Map(OpcodeToString)

// StringToRcode is a map of rcodes to strings.
var StringToRcode = reverse.Map(RcodeToString)

// StringToAlgorithm is the reverse of [AlgorithmToString].
var StringToAlgorithm = reverse.Map(AlgorithmToString)

// StringToHash is a map of names to hash IDs.
var StringToHash = reverse.Map(HashToString)

// StringToCertType is the reverse of [CertTypeToString].
var StringToCertType = reverse.Map(CertTypeToString)
