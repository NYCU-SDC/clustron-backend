package internal

import (
	"bufio"
	"os"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

var LinuxUserBlacklist = map[string]struct{}{
	// Core System Users
	"root":          {},
	"daemon":        {},
	"bin":           {},
	"sys":           {},
	"sync":          {},
	"games":         {},
	"man":           {},
	"lp":            {},
	"mail":          {},
	"news":          {},
	"uucp":          {},
	"proxy":         {},
	"admin":         {},
	"administrator": {},

	// Service-Specific Accounts
	"syslog":     {},
	"www-data":   {},
	"backup":     {},
	"list":       {},
	"irc":        {},
	"gnats":      {},
	"nobody":     {},
	"nogroup":    {},
	"messagebus": {},
	"sshd":       {},

	// Modern Systemd / Virtual Users
	"systemd-network":  {},
	"systemd-resolve":  {},
	"systemd-timesync": {},
	"systemd-coredump": {},
	"_apt":             {},
	"uuidd":            {},
	"tcpdump":          {},

	// Database and Common App Defaults
	"mysql":    {},
	"postgres": {},
	"apache":   {},
	"nginx":    {},
	"postfix":  {},

	// suggested system name
	"dhcpcd":        {},
	"pollinate":     {},
	"polkitd":       {},
	"tss":           {},
	"landscape":     {},
	"fwupd-refresh": {},
	"usbmux":        {},
	"sssd":          {},
}

func NewValidator() *validator.Validate {
	v := validator.New()
	err := loadSystemUsers()
	if err != nil {
		panic(err)
	}
	err = v.RegisterValidation("regexp", validateRegex)
	if err != nil {
		panic(err)
	}
	err = v.RegisterValidation("linux_username_format", validateLinuxUsernameFormat)
	if err != nil {
		panic(err)
	}
	err = v.RegisterValidation("linux_username_blacklist", validateLinuxUsernameBlacklist)
	if err != nil {
		panic(err)
	}
	return v
}

func validateRegex(fl validator.FieldLevel) bool {
	pattern := fl.Param()

	value := fl.Field().String()

	matched, err := regexp.MatchString(pattern, value)
	if err != nil {
		return false
	}
	return matched
}

func validateLinuxUsernameFormat(fl validator.FieldLevel) bool {
	value := fl.Field().String()

	pattern := `^[a-z_][a-z0-9_-]*[$]?$`
	matched, err := regexp.MatchString(pattern, value)
	if err != nil {
		return false
	}

	return matched
}

func validateLinuxUsernameBlacklist(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if _, exists := LinuxUserBlacklist[value]; exists {
		return false
	}
	return true
}

func loadSystemUsers() error {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		closeErr := file.Close()
		if err != nil {
			err = closeErr
		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines or comments
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		// /etc/passwd format: name:password:UID:GID:comment:home:shell
		parts := strings.Split(line, ":")
		if len(parts) > 0 {
			username := strings.ToLower(strings.TrimSpace(parts[0]))
			if username != "" {
				LinuxUserBlacklist[username] = struct{}{}
			}
		}
	}

	return scanner.Err()
}
