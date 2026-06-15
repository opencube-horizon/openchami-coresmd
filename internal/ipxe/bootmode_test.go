// SPDX-FileCopyrightText: © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package ipxe

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/iana"
)

func TestIsHTTPBootClient(t *testing.T) {
	mkReqWithClass := func(classID string) *dhcpv4.DHCPv4 {
		req := &dhcpv4.DHCPv4{
			ClientHWAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5},
			Options:      dhcpv4.Options{},
		}
		if classID != "" {
			req.Options.Update(dhcpv4.OptClassIdentifier(classID))
		}
		return req
	}

	mkReqWithArch := func(arch iana.Arch) *dhcpv4.DHCPv4 {
		req := &dhcpv4.DHCPv4{
			ClientHWAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5},
			Options:      dhcpv4.Options{},
		}
		archBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(archBytes, uint16(arch))
		req.Options.Update(dhcpv4.Option{
			Code:  dhcpv4.OptionClientSystemArchitectureType,
			Value: dhcpv4.OptionGeneric{Data: archBytes},
		})
		return req
	}

	tests := []struct {
		name string
		req  *dhcpv4.DHCPv4
		want bool
	}{
		{"class_HTTPClient", mkReqWithClass("HTTPClient:Arch:00016"), true},
		{"class_HTTPClient_plain", mkReqWithClass("HTTPClient"), true},
		{"class_PXEClient", mkReqWithClass("PXEClient:Arch:00000"), false},
		{"class_empty", mkReqWithClass(""), false},
		{"no_options", &dhcpv4.DHCPv4{Options: dhcpv4.Options{}}, false},

		{"arch_EFI_X86_HTTP", mkReqWithArch(iana.EFI_X86_HTTP), true},
		{"arch_EFI_X86_64_HTTP", mkReqWithArch(iana.EFI_X86_64_HTTP), true},
		{"arch_EFI_ARM32_HTTP", mkReqWithArch(iana.EFI_ARM32_HTTP), true},
		{"arch_EFI_ARM64_HTTP", mkReqWithArch(iana.EFI_ARM64_HTTP), true},
		{"arch_EFI_BC_HTTP", mkReqWithArch(iana.EFI_BC_HTTP), true},

		{"arch_INTEL_X86PC", mkReqWithArch(iana.INTEL_X86PC), false},
		{"arch_EFI_X86_64", mkReqWithArch(iana.EFI_X86_64), false},
		{"arch_EFI_IA32", mkReqWithArch(iana.EFI_IA32), false},
		{"arch_EFI_ARM64", mkReqWithArch(iana.EFI_ARM64), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsHTTPBootClient(tt.req); got != tt.want {
				t.Fatalf("IsHTTPBootClient()=%v want %v", got, tt.want)
			}
		})
	}
}

func TestServeHTTPBoot(t *testing.T) {
	baseURL := "http://10.0.0.1:8080/boot-assets/ipxe-{arch}.efi"

	mkReq := func(arch iana.Arch) *dhcpv4.DHCPv4 {
		req := &dhcpv4.DHCPv4{
			ClientHWAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5},
			Options:      dhcpv4.Options{},
		}
		req.Options.Update(dhcpv4.OptClientArch(arch))
		return req
	}
	mkResp := func() *dhcpv4.DHCPv4 { return &dhcpv4.DHCPv4{Options: dhcpv4.Options{}} }

	tests := []struct {
		name     string
		req      *dhcpv4.DHCPv4
		baseURI  string
		wantOK   bool
		wantBoot string
	}{
		{"x86_64_http", mkReq(iana.EFI_X86_64_HTTP), baseURL, true, "http://10.0.0.1:8080/boot-assets/ipxe-x86_64.efi"},
		{"x86_64_normal", mkReq(iana.EFI_X86_64), baseURL, true, "http://10.0.0.1:8080/boot-assets/ipxe-x86_64.efi"},
		{"ia32_http", mkReq(iana.EFI_X86_HTTP), baseURL, true, "http://10.0.0.1:8080/boot-assets/ipxe-i386.efi"},
		{"ia32_normal", mkReq(iana.EFI_IA32), baseURL, true, "http://10.0.0.1:8080/boot-assets/ipxe-i386.efi"},
		{"arm64_http", mkReq(iana.EFI_ARM64_HTTP), baseURL, true, "http://10.0.0.1:8080/boot-assets/ipxe-arm64.efi"},
		{"arm64_normal", mkReq(iana.EFI_ARM64), baseURL, true, "http://10.0.0.1:8080/boot-assets/ipxe-arm64.efi"},
		{"arm32_http", mkReq(iana.EFI_ARM32_HTTP), baseURL, true, "http://10.0.0.1:8080/boot-assets/ipxe-arm32.efi"},
		{"arm32_normal", mkReq(iana.EFI_ARM32), baseURL, true, "http://10.0.0.1:8080/boot-assets/ipxe-arm32.efi"},
		{"bc_http", mkReq(iana.EFI_BC_HTTP), baseURL, true, "http://10.0.0.1:8080/boot-assets/ipxe-x86_64.efi"},
		{"unknown_arch", mkReq(iana.Arch(999)), baseURL, false, ""},
		{"empty_base_uri", mkReq(iana.EFI_X86_64), "", false, ""},
		{"no_arch_option", &dhcpv4.DHCPv4{
			ClientHWAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5},
			Options:      dhcpv4.Options{},
		}, baseURL, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, ok := ServeHTTPBoot(nil, tt.req, mkResp(), tt.baseURI)
			if ok != tt.wantOK {
				t.Fatalf("ok=%v want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			got := string(resp.Options.Get(dhcpv4.OptionBootfileName))
			if got != tt.wantBoot {
				t.Fatalf("bootfile=%q want %q", got, tt.wantBoot)
			}
		})
	}
}
