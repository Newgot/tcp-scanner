package portscan

import (
	"fmt"
	"net"
	"strings"
)

// HostType определяет тип хоста
type HostType string

const (
	HostTypeIPv4    HostType = "ipv4"
	HostTypeIPv6    HostType = "ipv6"
	HostTypeDNS     HostType = "dns"
	HostTypeInvalid HostType = "invalid"
)

// HostInfo содержит информацию о хосте
type HostInfo struct {
	Original  string   // Исходное значение
	Type      HostType // Тип хоста
	Addresses []string // IP-адреса (после разрешения)
	IsValid   bool     // Валидный ли хост
	Error     error    // Ошибка при разрешении
}

// ResolveHosts разрешает список хостов в IP-адреса
func ResolveHosts(hosts []string) ([]HostInfo, error) {
	if len(hosts) == 0 {
		return nil, ErrNoHosts
	}

	var results []HostInfo
	seen := make(map[string]bool) // Для удаления дубликатов

	for _, host := range hosts {
		host = strings.TrimSpace(host)

		// Пропускаем пустые хосты
		if host == "" {
			results = append(results, HostInfo{
				Original: host,
				Type:     HostTypeInvalid,
				IsValid:  false,
				Error:    fmt.Errorf("empty hosts"),
			})
			continue
		}

		// Проверяем дубликаты
		if seen[host] {
			continue // Пропускаем дубликаты
		}
		seen[host] = true

		info := resolveHost(host)
		results = append(results, info)
	}

	return results, nil
}

// resolveHost разрешает один хост
func resolveHost(host string) HostInfo {
	// Проверяем, является ли хост IP-адресом
	if ip := net.ParseIP(host); ip != nil {
		// Определяем тип IP
		ipType := HostTypeIPv4
		if ip.To4() == nil {
			ipType = HostTypeIPv6
		}

		return HostInfo{
			Original:  host,
			Type:      ipType,
			Addresses: []string{host},
			IsValid:   true,
		}
	}

	// Пытаемся разрешить DNS-имя
	addrs, err := net.LookupHost(host)
	if err != nil {
		return HostInfo{
			Original: host,
			Type:     HostTypeInvalid,
			IsValid:  false,
			Error:    fmt.Errorf("failed to resolve hosts: %w", err),
		}
	}

	// Проверяем, есть ли результаты
	if len(addrs) == 0 {
		return HostInfo{
			Original: host,
			Type:     HostTypeInvalid,
			IsValid:  false,
			Error:    fmt.Errorf("no IP addresses found for hosts"),
		}
	}

	// Определяем тип DNS (может содержать IPv4 и IPv6)
	return HostInfo{
		Original:  host,
		Type:      HostTypeDNS,
		Addresses: addrs,
		IsValid:   true,
	}
}

// GetUniqueAddresses возвращает уникальные IP-адреса из списка хостов
func GetUniqueAddresses(hostsInfo []HostInfo) []string {
	seen := make(map[string]bool)
	var addresses []string

	for _, info := range hostsInfo {
		if !info.IsValid {
			continue
		}
		for _, addr := range info.Addresses {
			if !seen[addr] {
				seen[addr] = true
				addresses = append(addresses, addr)
			}
		}
	}

	return addresses
}

// ValidateHosts проверяет хосты и возвращает только валидные
func ValidateHosts(hosts []string) ([]HostInfo, error) {
	info, err := ResolveHosts(hosts)
	if err != nil {
		return nil, err
	}

	var valid []HostInfo
	var errors []string

	for _, h := range info {
		if h.IsValid {
			valid = append(valid, h)
		} else {
			errors = append(errors, fmt.Sprintf("%s: %v", h.Original, h.Error))
		}
	}

	if len(valid) == 0 && len(errors) > 0 {
		return nil, fmt.Errorf("no valid hosts: %s", strings.Join(errors, "; "))
	}

	return valid, nil
}
