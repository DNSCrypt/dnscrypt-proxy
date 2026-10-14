package revera

// Compilation flags.
// The library implements only the ERE language, so REG_EXTENDED is implicit and has no flag here.
const (
	// FlagICase applies the case-insensitive closure of section 10.2.
	FlagICase uint32 = 1
	// FlagNewline applies the four newline exceptions of section 12.3.
	FlagNewline uint32 = 2
	// FlagNoSub compiles for success or failure reporting only.
	FlagNoSub uint32 = 4
	// FlagMinimal makes every duplication shortest-preferring by default.
	// A repetition modifier then reverses one duplication back.
	FlagMinimal uint32 = 8
)

// Execution flags.
const (
	// ExecNotBOL removes the line boundary before the first character.
	ExecNotBOL uint32 = 1
	// ExecNotEOL removes the line boundary after the last character.
	ExecNotEOL uint32 = 2
)

// dupMax is the largest supported interval count.
// POSIX requires at least 255.
// DupMax in the host wrapper re-exports it.
const dupMax = 255
