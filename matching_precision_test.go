package credbridge_test

import (
	"encoding/json"
	"testing"

	"github.com/masv3971/credbridge"
	"github.com/stretchr/testify/assert"
)

func TestMatchValue_JSONNumberKeepsDecimalPrecision(t *testing.T) {
	assert.False(t, credbridge.MatchValue(json.Number("1.0000000000000001"), json.Number("1")))
	assert.False(t, credbridge.MatchValue(json.Number("1"), json.Number("1.0000000000000001")))
	assert.True(t, credbridge.MatchValue(json.Number("1.0"), json.Number("1e0")))
	assert.True(t, credbridge.MatchValue(float64(18), json.Number("18.0")))
	assert.False(t, credbridge.MatchValue(float64(18), json.Number("18.5")))
}

// A float matches the decimal it serialises to, not its binary expansion.
func TestMatchValue_FloatMatchesItsJSONDecimal(t *testing.T) {
	assert.True(t, credbridge.MatchValue(float64(0.1), json.Number("0.1")))
	assert.True(t, credbridge.MatchValue(json.Number("0.1"), float64(0.1)))
	assert.True(t, credbridge.MatchValue(float32(0.1), json.Number("0.1")))
	assert.True(t, credbridge.MatchValue(float64(1.5), json.Number("1.50")))
	assert.False(t, credbridge.MatchValue(float64(0.1), json.Number("0.10000000000000001")))
	assert.False(t, credbridge.MatchValue(float64(0.1), json.Number("0.2")))
}
