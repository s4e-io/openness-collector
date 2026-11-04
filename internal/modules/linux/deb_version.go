package linux

import (
	"strconv"
	"strings"
	"unicode"
)

// compareDebVersion compares Debian package versions (policy §5.6.12).
// Returns -1 if a<b, 0 if equal, 1 if a>b.
func compareDebVersion(a, b string) int {
	if a == b {
		return 0
	}
	ae, au, ad := splitDebVersion(a)
	be, bu, bd := splitDebVersion(b)
	if ae != be {
		if ae < be {
			return -1
		}
		return 1
	}
	if c := compareDebVersionPart(au, bu); c != 0 {
		return c
	}
	return compareDebVersionPart(ad, bd)
}

func splitDebVersion(v string) (epoch int, upstream, debian string) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if e, err := strconv.Atoi(v[:i]); err == nil {
			epoch = e
			v = v[i+1:]
		}
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

func compareDebVersionPart(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		na, ia := takeDebNonDigits(a, i)
		nb, jb := takeDebNonDigits(b, j)
		if c := compareDebNonDigit(na, nb); c != 0 {
			return c
		}
		i, j = ia, jb

		da, ia := takeDebDigits(a, i)
		db, jb := takeDebDigits(b, j)
		if da != db {
			if da < db {
				return -1
			}
			return 1
		}
		i, j = ia, jb
	}
	return 0
}

func takeDebNonDigits(s string, i int) (part string, next int) {
	next = i
	for next < len(s) && !unicode.IsDigit(rune(s[next])) {
		next++
	}
	return s[i:next], next
}

func takeDebDigits(s string, i int) (val int, next int) {
	next = i
	for next < len(s) && unicode.IsDigit(rune(s[next])) {
		next++
	}
	if next == i {
		return 0, i
	}
	n, err := strconv.Atoi(s[i:next])
	if err != nil {
		return len(s[i:next]), next
	}
	return n, next
}

func compareDebNonDigit(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		wa, ia := debCharWeight(a, i)
		wb, jb := debCharWeight(b, j)
		if wa != wb {
			if wa < wb {
				return -1
			}
			return 1
		}
		i, j = ia, jb
	}
	return 0
}

// debCharWeight: end-of-string = 0; '~' = -1; letters = codepoint; others = codepoint+256.
func debCharWeight(s string, i int) (weight int, next int) {
	if i >= len(s) {
		return 0, i
	}
	r := rune(s[i])
	next = i + 1
	if r == '~' {
		return -1, next
	}
	if unicode.IsLetter(r) {
		return int(r), next
	}
	return int(r) + 256, next
}
