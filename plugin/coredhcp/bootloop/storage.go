// SPDX-FileCopyrightText: © 2024-2025 Triad National Security, LLC.
// SPDX-FileCopyrightText: © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package bootloop

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"

	bolt "go.etcd.io/bbolt"
)

var bucketLeases4 = []byte("leases4")

type leaseRecord struct {
	IP       string `json:"IP"`
	Expiry   int    `json:"Expiry"`
	Hostname string `json:"Hostname"`
}

func loadDB(path string) (*bolt.DB, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open database (%T): %w", err, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketLeases4)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("table creation failed: %w", err)
	}
	return db, nil
}

// loadRecords loads the DHCPv6/v4 Records global map with records stored on
// the specified file. The records have to be one per line, a mac address and an
// IP address.
func loadRecords(db *bolt.DB) (map[string]*Record, error) {
	records := make(map[string]*Record)
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketLeases4)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			mac := string(k)
			hwaddr, err := net.ParseMAC(mac)
			if err != nil {
				return fmt.Errorf("malformed hardware address: %s", mac)
			}
			var lr leaseRecord
			if err := json.Unmarshal(v, &lr); err != nil {
				return fmt.Errorf("failed to scan row: %w", err)
			}
			ipaddr := net.ParseIP(lr.IP)
			if ipaddr.To4() == nil {
				return fmt.Errorf("expected an IPv4 address, got: %v", ipaddr)
			}
			records[hwaddr.String()] = &Record{IP: ipaddr, expires: lr.Expiry, hostname: lr.Hostname}
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query leases database: %w", err)
	}
	return records, nil
}

// deleteIPAddress deletes a lease from storage
func (p *PluginState) deleteIPAddress(mac net.HardwareAddr) error {
	if err := p.leasedb.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketLeases4)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(mac.String()))
	}); err != nil {
		return fmt.Errorf("record delete failed: %w", err)
	}
	return nil
}

// saveIPAddress writes out a lease to storage
func (p *PluginState) saveIPAddress(mac net.HardwareAddr, record *Record) error {
	data, err := json.Marshal(leaseRecord{
		IP:       record.IP.String(),
		Expiry:   record.expires,
		Hostname: record.hostname,
	})
	if err != nil {
		return fmt.Errorf("record insert/update failed: %w", err)
	}
	if err := p.leasedb.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketLeases4)
		if b == nil {
			return fmt.Errorf("leases4 bucket not found")
		}
		return b.Put([]byte(mac.String()), data)
	}); err != nil {
		return fmt.Errorf("record insert/update failed: %w", err)
	}
	return nil
}

// registerBackingDB installs a database connection string as the backing store for leases
func (p *PluginState) registerBackingDB(filename string) error {
	if p.leasedb != nil {
		return errors.New("cannot swap out a lease database while running")
	}
	// We never close this, but that's ok because plugins are never stopped/unregistered
	newLeaseDB, err := loadDB(filename)
	if err != nil {
		return fmt.Errorf("failed to open lease database %s: %w", filename, err)
	}
	p.leasedb = newLeaseDB
	return nil
}
