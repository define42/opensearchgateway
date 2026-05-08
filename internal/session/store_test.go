package session

import (
	"testing"
	"time"
)

func TestStoreExpiresSessions(t *testing.T) {
	t.Run("get removes expired session", func(t *testing.T) {
		store := NewStore()
		store.sessions["expired"] = Data{ExpiresAt: time.Now().Add(-time.Minute)}

		if _, ok := store.Get("expired"); ok {
			t.Fatal("expected expired session get to fail")
		}
		if _, ok := store.sessions["expired"]; ok {
			t.Fatal("expected expired session to be removed")
		}
	})

	t.Run("touch removes expired session", func(t *testing.T) {
		store := NewStore()
		store.sessions["expired"] = Data{ExpiresAt: time.Now().Add(-time.Minute)}

		if _, ok := store.Touch("expired"); ok {
			t.Fatal("expected expired session touch to fail")
		}
		if _, ok := store.sessions["expired"]; ok {
			t.Fatal("expected expired session to be removed")
		}
	})
}
