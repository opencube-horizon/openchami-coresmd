// SPDX-FileCopyrightText: © 2024-2025 Triad National Security, LLC.
// SPDX-FileCopyrightText: © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package bootloop

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func openTestDB(t *testing.T) *bolt.DB {
	t.Helper()

	path := filepath.Join(t.TempDir(), "leases.db")
	db, err := loadDB(path)
	if err != nil {
		t.Fatalf("loadDB(%q) error = %v", path, err)
	}
	return db
}

func TestLoadDB(t *testing.T) {
	tests := []struct {
		name string
	}{{
		name: "creates_leases4_bucket",
	}, {
		name: "idempotent_on_existing_db",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "leases.db")

			db1, err := loadDB(path)
			if err != nil {
				t.Fatalf("first loadDB(%q) error = %v", path, err)
			}

			if err := db1.View(func(tx *bolt.Tx) error {
				if tx.Bucket([]byte("leases4")) == nil {
					t.Fatalf("leases4 bucket not found after loadDB")
				}
				return nil
			}); err != nil {
				t.Fatalf("bucket check failed: %v", err)
			}

			db1.Close()

			db2, err := loadDB(path)
			if err != nil {
				t.Fatalf("second loadDB(%q) error = %v", path, err)
			}
			defer db2.Close()
		})
	}
}

func TestLoadRecords(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, db *bolt.DB)
		wantErrSub string
		wantLen    int
		wantKey    string
		wantRecord *Record
	}{
		{
			name: "empty_table_returns_empty_map",
			setup: func(t *testing.T, db *bolt.DB) {
			},
			wantLen: 0,
		},
		{
			name: "single_valid_row_loaded",
			setup: func(t *testing.T, db *bolt.DB) {
				const macStr = "aa:bb:cc:dd:ee:ff"
				err := db.Update(func(tx *bolt.Tx) error {
					b := tx.Bucket([]byte("leases4"))
					if b == nil {
						return fmt.Errorf("bucket not found")
					}
					data, err := json.Marshal(leaseRecord{IP: "192.168.1.10", Expiry: 123, Hostname: "test-host"})
					if err != nil {
						return err
					}
					return b.Put([]byte(macStr), data)
				})
				if err != nil {
					t.Fatalf("insert test lease: %v", err)
				}
			},
			wantLen: 1,
			wantKey: "aa:bb:cc:dd:ee:ff",
			wantRecord: &Record{
				IP:       net.ParseIP("192.168.1.10"),
				expires:  123,
				hostname: "test-host",
			},
		},
		{
			name: "invalid_mac_gives_error",
			setup: func(t *testing.T, db *bolt.DB) {
				err := db.Update(func(tx *bolt.Tx) error {
					b := tx.Bucket([]byte("leases4"))
					if b == nil {
						return fmt.Errorf("bucket not found")
					}
					data, err := json.Marshal(leaseRecord{IP: "192.168.1.10", Expiry: 123, Hostname: "bad-mac-host"})
					if err != nil {
						return err
					}
					return b.Put([]byte("zz:zz:zz:zz:zz:zz"), data)
				})
				if err != nil {
					t.Fatalf("insert invalid mac lease: %v", err)
				}
			},
			wantErrSub: "malformed hardware address",
			wantLen:    0,
		},
		{
			name: "non_ipv4_address_gives_error",
			setup: func(t *testing.T, db *bolt.DB) {
				err := db.Update(func(tx *bolt.Tx) error {
					b := tx.Bucket([]byte("leases4"))
					if b == nil {
						return fmt.Errorf("bucket not found")
					}
					data, err := json.Marshal(leaseRecord{IP: "2001:db8::1", Expiry: 456, Hostname: "ipv6-host"})
					if err != nil {
						return err
					}
					return b.Put([]byte("aa:bb:cc:dd:ee:ff"), data)
				})
				if err != nil {
					t.Fatalf("insert ipv6 lease: %v", err)
				}
			},
			wantErrSub: "expected an IPv4 address",
			wantLen:    0,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			db := openTestDB(t)
			defer db.Close()

			if tt.setup != nil {
				tt.setup(t, db)
			}

			records, err := loadRecords(db)

			if tt.wantErrSub != "" {
				if err == nil {
					t.Fatalf("loadRecords() error = nil, want substring %q", tt.wantErrSub)
				}
				if !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Fatalf("loadRecords() error = %v, want substring %q", err, tt.wantErrSub)
				}
				return
			}

			if err != nil {
				t.Fatalf("loadRecords() unexpected error = %v", err)
			}

			if gotLen := len(records); gotLen != tt.wantLen {
				t.Fatalf("loadRecords() len(records) = %d, want %d", gotLen, tt.wantLen)
			}

			if tt.wantRecord != nil {
				rec, ok := records[tt.wantKey]
				if !ok {
					t.Fatalf("loadRecords() missing key %q in records map", tt.wantKey)
				}
				if !rec.IP.Equal(tt.wantRecord.IP) {
					t.Errorf("record.IP = %v, want %v", rec.IP, tt.wantRecord.IP)
				}
				if rec.expires != tt.wantRecord.expires {
					t.Errorf("record.expires = %d, want %d", rec.expires, tt.wantRecord.expires)
				}
				if rec.hostname != tt.wantRecord.hostname {
					t.Errorf("record.hostname = %q, want %q", rec.hostname, tt.wantRecord.hostname)
				}
			}
		})
	}
}

func TestDeleteIPAddress(t *testing.T) {
	tests := []struct {
		name           string
		setup          func(t *testing.T) (*PluginState, net.HardwareAddr)
		wantErrSub     string
		wantKeyExists  bool
		checkRemaining bool
	}{
		{
			name: "delete_existing_lease",
			setup: func(t *testing.T) (*PluginState, net.HardwareAddr) {
				db := openTestDB(t)
				mac, err := net.ParseMAC("00:11:22:33:44:55")
				if err != nil {
					t.Fatalf("ParseMAC: %v", err)
				}
				err = db.Update(func(tx *bolt.Tx) error {
					b := tx.Bucket([]byte("leases4"))
					if b == nil {
						return fmt.Errorf("bucket not found")
					}
					data, _ := json.Marshal(leaseRecord{IP: "192.168.1.20", Expiry: 111, Hostname: "delete-me"})
					return b.Put([]byte(mac.String()), data)
				})
				if err != nil {
					t.Fatalf("insert lease: %v", err)
				}
				return &PluginState{leasedb: db}, mac
			},
			wantKeyExists:  false,
			checkRemaining: true,
		},
		{
			name: "delete_nonexistent_lease_no_error",
			setup: func(t *testing.T) (*PluginState, net.HardwareAddr) {
				db := openTestDB(t)
				mac, err := net.ParseMAC("aa:bb:cc:dd:ee:ff")
				if err != nil {
					t.Fatalf("ParseMAC: %v", err)
				}
				return &PluginState{leasedb: db}, mac
			},
			wantKeyExists:  false,
			checkRemaining: true,
		},
		{
			name: "closed_db_causes_error",
			setup: func(t *testing.T) (*PluginState, net.HardwareAddr) {
				db := openTestDB(t)
				db.Close()
				mac, err := net.ParseMAC("00:11:22:33:44:55")
				if err != nil {
					t.Fatalf("ParseMAC: %v", err)
				}
				return &PluginState{leasedb: db}, mac
			},
			wantErrSub:     "record delete failed",
			checkRemaining: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			p, mac := tt.setup(t)
			defer func() {
				if p.leasedb != nil {
					p.leasedb.Close()
				}
			}()

			err := p.deleteIPAddress(mac)

			if tt.wantErrSub != "" {
				if err == nil {
					t.Fatalf("deleteIPAddress() error = nil, want substring %q", tt.wantErrSub)
				}
				if !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Fatalf("deleteIPAddress() error = %v, want substring %q", err, tt.wantErrSub)
				}
				return
			}

			if err != nil {
				t.Fatalf("deleteIPAddress() unexpected error = %v", err)
			}

			if tt.checkRemaining {
				var keyExists bool
				if viewErr := p.leasedb.View(func(tx *bolt.Tx) error {
					b := tx.Bucket([]byte("leases4"))
					if b != nil && b.Get([]byte(mac.String())) != nil {
						keyExists = true
					}
					return nil
				}); viewErr != nil {
					t.Fatalf("key existence check failed: %v", viewErr)
				}
				if keyExists != tt.wantKeyExists {
					t.Fatalf("key %s exists = %v, want %v", mac.String(), keyExists, tt.wantKeyExists)
				}
			}
		})
	}
}

func TestSaveIPAddress(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T) *PluginState
		mac        string
		record     *Record
		wantErrSub string
	}{
		{
			name: "insert_new_lease",
			setup: func(t *testing.T) *PluginState {
				db := openTestDB(t)
				return &PluginState{leasedb: db}
			},
			mac: "00:11:22:33:44:55",
			record: &Record{
				IP:       net.ParseIP("192.168.1.30"),
				expires:  222,
				hostname: "insert-host",
			},
		},
		{
			name: "closed_db_causes_error",
			setup: func(t *testing.T) *PluginState {
				db := openTestDB(t)
				db.Close()
				return &PluginState{leasedb: db}
			},
			mac: "aa:bb:cc:dd:ee:ff",
			record: &Record{
				IP:       net.ParseIP("192.168.1.40"),
				expires:  333,
				hostname: "closed-db-host",
			},
			wantErrSub: "record insert/update failed",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			p := tt.setup(t)
			defer func() {
				if p.leasedb != nil {
					p.leasedb.Close()
				}
			}()

			mac, err := net.ParseMAC(tt.mac)
			if err != nil {
				t.Fatalf("ParseMAC(%q): %v", tt.mac, err)
			}

			err = p.saveIPAddress(mac, tt.record)

			if tt.wantErrSub != "" {
				if err == nil {
					t.Fatalf("saveIPAddress() error = nil, want substring %q", tt.wantErrSub)
				}
				if !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Fatalf("saveIPAddress() error = %v, want substring %q", err, tt.wantErrSub)
				}
				return
			}

			if err != nil {
				t.Fatalf("saveIPAddress() unexpected error = %v", err)
			}

			var stored leaseRecord
			if viewErr := p.leasedb.View(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte("leases4"))
				if b == nil {
					return fmt.Errorf("bucket not found")
				}
				v := b.Get([]byte(mac.String()))
				if v == nil {
					return fmt.Errorf("key %s not found", mac.String())
				}
				return json.Unmarshal(v, &stored)
			}); viewErr != nil {
				t.Fatalf("select lease failed: %v", viewErr)
			}
			if stored.IP != tt.record.IP.String() {
				t.Errorf("stored ip = %q, want %q", stored.IP, tt.record.IP.String())
			}
			if stored.Expiry != tt.record.expires {
				t.Errorf("stored expiry = %d, want %d", stored.Expiry, tt.record.expires)
			}
			if stored.Hostname != tt.record.hostname {
				t.Errorf("stored hostname = %q, want %q", stored.Hostname, tt.record.hostname)
			}
		})
	}
}

func TestRegisterBackingDB(t *testing.T) {
	tests := []struct {
		name       string
		initialDB  *bolt.DB
		wantErrSub string
		check      func(t *testing.T, p *PluginState)
	}{
		{
			name:      "sets_db_when_nil",
			initialDB: nil,
			check: func(t *testing.T, p *PluginState) {
				if p.leasedb == nil {
					t.Fatalf("leasedb is nil after successful registerBackingDB")
				}
			},
		},
		{
			name:       "errors_when_db_already_set",
			initialDB:  &bolt.DB{},
			wantErrSub: "cannot swap out a lease database while running",
			check: func(t *testing.T, p *PluginState) {
				if p.leasedb == nil {
					t.Fatalf("leasedb was cleared unexpectedly")
				}
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var p PluginState
			p.leasedb = tt.initialDB

			filename := filepath.Join(t.TempDir(), "leases.db")
			err := p.registerBackingDB(filename)

			if tt.wantErrSub != "" {
				if err == nil {
					t.Fatalf("registerBackingDB() error = nil, want substring %q", tt.wantErrSub)
				}
				if !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Fatalf("registerBackingDB() error = %v, want substring %q", err, tt.wantErrSub)
				}
			} else if err != nil {
				t.Fatalf("registerBackingDB() unexpected error = %v", err)
			}

			tt.check(t, &p)

			if tt.initialDB == nil && p.leasedb != nil {
				p.leasedb.Close()
			}
		})
	}
}
