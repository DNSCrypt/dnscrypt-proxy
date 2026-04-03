package main

// AhoCorasick implements the Aho-Corasick multi-pattern string matching automaton.
// It finds all occurrences of any pattern in a text in O(n + z) time, where n is
// the text length and z is the number of matches, compared to O(K×n×m) for a
// naive linear scan of K patterns.
type AhoCorasick struct {
	states  []acState
	built   bool
	pattern []string // original patterns by index
}

type acState struct {
	goto_   [256]int32 // goto function for each byte; -1 = no transition
	fail    int32      // failure link
	output  int32      // index of the first matching pattern, -1 = none
	dictSuf int32      // dictionary suffix link for chaining outputs, -1 = none
}

// NewAhoCorasick creates a new Aho-Corasick automaton.
func NewAhoCorasick() *AhoCorasick {
	ac := &AhoCorasick{}
	// State 0 is the root
	ac.states = append(ac.states, newACState())
	return ac
}

func newACState() acState {
	var s acState
	for i := range s.goto_ {
		s.goto_[i] = -1
	}
	s.fail = 0
	s.output = -1
	s.dictSuf = -1
	return s
}

// AddPattern adds a pattern to the automaton. Must be called before Build().
func (ac *AhoCorasick) AddPattern(pattern string) {
	state := int32(0)
	for i := range len(pattern) {
		c := pattern[i]
		if ac.states[state].goto_[c] == -1 {
			ac.states[state].goto_[c] = int32(len(ac.states))
			ac.states = append(ac.states, newACState())
		}
		state = ac.states[state].goto_[c]
	}
	idx := int32(len(ac.pattern))
	ac.pattern = append(ac.pattern, pattern)
	ac.states[state].output = idx
}

// Build constructs the failure and dictionary-suffix links using BFS.
func (ac *AhoCorasick) Build() {
	// BFS queue
	queue := make([]int32, 0, len(ac.states))

	// Initialize: all root transitions that go nowhere loop back to root
	for c := range 256 {
		if ac.states[0].goto_[c] == -1 {
			ac.states[0].goto_[c] = 0 // self-loop at root
		} else {
			s := ac.states[0].goto_[c]
			ac.states[s].fail = 0
			queue = append(queue, s)
		}
	}

	// BFS to build failure links
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]

		for c := range 256 {
			s := ac.states[r].goto_[c]
			if s == -1 {
				// Fill in missing transitions using failure links
				ac.states[r].goto_[c] = ac.states[ac.states[r].fail].goto_[c]
				continue
			}
			queue = append(queue, s)
			failState := ac.states[r].fail
			for ac.states[failState].goto_[c] == -1 {
				failState = ac.states[failState].fail
			}
			ac.states[s].fail = ac.states[failState].goto_[c]
			if ac.states[s].fail == s {
				ac.states[s].fail = 0
			}
			// Set dictionary suffix link
			if ac.states[ac.states[s].fail].output >= 0 {
				ac.states[s].dictSuf = ac.states[s].fail
			} else {
				ac.states[s].dictSuf = ac.states[ac.states[s].fail].dictSuf
			}
		}
	}

	ac.built = true
}

// ContainsAny returns true if text contains any of the added patterns,
// along with the index of the first matching pattern found.
// Returns (false, -1) if no match.
func (ac *AhoCorasick) ContainsAny(text string) (bool, int) {
	if !ac.built || len(ac.pattern) == 0 {
		return false, -1
	}
	state := int32(0)
	for i := range len(text) {
		c := text[i]
		state = ac.states[state].goto_[c]
		// Check for match at current state
		if ac.states[state].output >= 0 {
			return true, int(ac.states[state].output)
		}
		// Check dictionary suffix chain
		if ac.states[state].dictSuf >= 0 {
			return true, int(ac.states[ac.states[state].dictSuf].output)
		}
	}
	return false, -1
}

// PatternCount returns the number of patterns added.
func (ac *AhoCorasick) PatternCount() int {
	return len(ac.pattern)
}

// Pattern returns the pattern at index i.
func (ac *AhoCorasick) Pattern(i int) string {
	return ac.pattern[i]
}
