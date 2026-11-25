package credbridge

import (
	"encoding/json"
	"math"
	"math/big"
	"strconv"
)

// MatchValue implements the claim-value matching rules of Appendix C.
//
// Two values match when they have the same JSON type and are equal under
// these rules:
//   - Strings compared as sequences of Unicode code points (no
//     normalization, no case folding, no whitespace trimming).
//   - Numbers compared by mathematical value; integer-valued float64s
//     within the IEEE-754 safe integer range match equal ints.
//   - Booleans and null match only themselves.
//   - Arrays match element-wise, recursively, in order.
//   - Objects match by member set and per-member value, recursively.
//
// Values of different JSON types never match. In particular the string
// "1" does not match the number 1.
func MatchValue(disclosed, expected any) bool {
	switch e := expected.(type) {
	case string:
		d, ok := disclosed.(string)
		return ok && d == e
	case bool:
		d, ok := disclosed.(bool)
		return ok && d == e
	case nil:
		return disclosed == nil
	case []any:
		d, ok := disclosed.([]any)
		if !ok || len(d) != len(e) {
			return false
		}
		for i := range e {
			if !MatchValue(d[i], e[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		d, ok := disclosed.(map[string]any)
		if !ok || len(d) != len(e) {
			return false
		}
		for k, ev := range e {
			dv, present := d[k]
			if !present || !MatchValue(dv, ev) {
				return false
			}
		}
		return true
	}
	// A json.Number carries its exact decimal literal; a float64 round trip
	// would equate 1.0000000000000001 with 1.
	if en, ok := expected.(json.Number); ok {
		return matchExactNumber(disclosed, en)
	}
	if dn, ok := disclosed.(json.Number); ok {
		return matchExactNumber(expected, dn)
	}
	// Numeric types: normalise to float64 and require both sides numeric.
	ef, eok := toFloat64(expected)
	df, dok := toFloat64(disclosed)
	if !eok || !dok {
		return false
	}
	return ef == df
}

// matchExactNumber compares other with n as exact rationals. A float is
// taken at its shortest decimal form, the way it serialises to JSON, so
// float64(0.1) equals json.Number("0.1"). A non-JSON number type that is
// not exactly representable never matches.
func matchExactNumber(other any, n json.Number) bool {
	nr, ok := new(big.Rat).SetString(n.String())
	if !ok {
		return false
	}
	var or *big.Rat
	switch o := other.(type) {
	case json.Number:
		or, ok = new(big.Rat).SetString(o.String())
		if !ok {
			return false
		}
	case float64, float32, int, int32, int64, uint, uint32, uint64:
		f, ok := toFloat64(o)
		if !ok {
			return false
		}
		bits := 64
		if _, isFloat32 := o.(float32); isFloat32 {
			bits = 32
		}
		or, ok = new(big.Rat).SetString(strconv.FormatFloat(f, 'g', -1, bits))
		if !ok {
			return false
		}
	default:
		return false
	}
	return nr.Cmp(or) == 0
}

// toFloat64 normalises a numeric value to float64 for Appendix C
// mathematical comparison, honouring the IEEE-754 safe integer range.
func toFloat64(v any) (float64, bool) {
	const maxSafe = float64(1<<53 - 1)
	switch n := v.(type) {
	case int:
		return toFloat64(int64(n))
	case int32:
		return float64(n), true
	case int64:
		f := float64(n)
		return f, n == int64(f)
	case uint:
		return toFloat64(uint64(n))
	case uint32:
		return float64(n), true
	case uint64:
		f := float64(n)
		return f, n == uint64(f)
	case float32:
		return float64(n), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return toFloat64(i)
		}
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return toFloat64(f)
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return 0, false
		}
		// An integral value beyond the IEEE-754 safe range cannot be
		// compared without conflating distinct JSON integers (encoding/json
		// rounds e.g. 9007199254740993 to ...992), so fail closed.
		if n == math.Trunc(n) && (n > maxSafe || n < -maxSafe) {
			return 0, false
		}
		return n, true
	}
	return 0, false
}
