package credbridge_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A live caller waiting on a fetch that another caller's context aborted
// must fetch again rather than inherit that cancellation.
func TestRP_Discover_WaiterRetriesAfterCancelledFetch(t *testing.T) {
	var requests atomic.Int32
	started := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			started <- struct{}{}
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte(`{"issuer":"http://` + r.Host + `","authorization_endpoint":"a","token_endpoint":"t"}`))
	}))
	defer srv.Close()
	rp := newRP(t, srv.URL, srv.Client(), true)

	ctx1, cancel1 := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel1()
	go func() { _, _ = rp.Discover(ctx1) }()
	<-started

	ctx2, cancel2 := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel2()
	md, err := rp.Discover(ctx2)
	require.NoError(t, err)
	assert.Equal(t, srv.URL, md.Issuer)
	assert.EqualValues(t, 2, requests.Load())
}
