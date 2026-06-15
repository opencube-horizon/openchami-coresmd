// SPDX-FileCopyrightText: © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package ipxe

import (
	"encoding/binary"
	"strings"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/sirupsen/logrus"
)

func IsHTTPBootClient(req *dhcpv4.DHCPv4) bool {
	if strings.HasPrefix(req.ClassIdentifier(), "HTTPClient") {
		return true
	}
	if req.Options.Has(dhcpv4.OptionClientSystemArchitectureType) {
		archBytes := req.Options.Get(dhcpv4.OptionClientSystemArchitectureType)
		if len(archBytes) >= 2 {
			arch := iana.Arch(binary.BigEndian.Uint16(archBytes))
			switch arch {
			case iana.EFI_X86_HTTP, iana.EFI_X86_64_HTTP,
				iana.EFI_ARM32_HTTP, iana.EFI_ARM64_HTTP,
				iana.EFI_BC_HTTP:
				return true
			}
		}
	}
	return false
}

func ServeHTTPBoot(l *logrus.Entry, req, resp *dhcpv4.DHCPv4, httpBootURL string) (*dhcpv4.DHCPv4, bool) {
	if l == nil {
		l = logrus.NewEntry(logrus.New())
	}
	if httpBootURL == "" {
		l.Error("ServeHTTPBoot called with empty URL")
		return resp, false
	}

	bootURL := httpBootURL
	if strings.Contains(bootURL, "{arch}") {
		arch := resolveArch(req)
		if arch == "" {
			l.WithField("mac", req.ClientHWAddr).Info("URL contains {arch} but client did not present a recognized architecture")
			return resp, false
		}
		bootURL = strings.ReplaceAll(bootURL, "{arch}", arch)
	}

	resp.Options.Update(dhcpv4.OptClassIdentifier("HTTPClient"))
	resp.Options.Update(dhcpv4.OptBootFileName(bootURL))
	l.WithFields(logrus.Fields{
		"mac":      req.ClientHWAddr,
		"boot_url": bootURL,
	}).Info("HTTP Boot: serving boot URL")
	return resp, true
}

func resolveArch(req *dhcpv4.DHCPv4) string {
	if !req.Options.Has(dhcpv4.OptionClientSystemArchitectureType) {
		return ""
	}
	archBytes := req.Options.Get(dhcpv4.OptionClientSystemArchitectureType)
	if len(archBytes) < 2 {
		return ""
	}
	switch iana.Arch(binary.BigEndian.Uint16(archBytes)) {
	case iana.EFI_X86_64, iana.EFI_X86_64_HTTP:
		return "x86_64"
	case iana.EFI_IA32, iana.EFI_X86_HTTP:
		return "i386"
	case iana.EFI_ARM64, iana.EFI_ARM64_HTTP:
		return "arm64"
	case iana.EFI_ARM32, iana.EFI_ARM32_HTTP:
		return "arm32"
	case iana.EFI_BC_HTTP:
		return "x86_64"
	default:
		return ""
	}
}
