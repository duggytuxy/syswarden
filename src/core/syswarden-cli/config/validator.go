package config

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate
var countryCodeRegex = regexp.MustCompile("^[a-zA-Z]{2}$")

func init() {
	validate = validator.New()
	_ = validate.RegisterValidation("cidr", validateCIDR)
	_ = validate.RegisterValidation("cidr_slice", validateCIDRSlice)
	_ = validate.RegisterValidation("ip", validateIP)
	_ = validate.RegisterValidation("ip_slice", validateIPSlice)
	_ = validate.RegisterValidation("port", validatePort)
	_ = validate.RegisterValidation("port_slice", validatePortSlice)
	_ = validate.RegisterValidation("asn", validateASN)
	_ = validate.RegisterValidation("asn_slice", validateASNSlice)
	_ = validate.RegisterValidation("country_code", validateCountryCode)
	_ = validate.RegisterValidation("country_code_slice", validateCountryCodeSlice)
	_ = validate.RegisterValidation("duration", validateDuration)
}

func validateConfig(config *ModularConfig) error {
	return validate.Struct(config)
}

func validateCIDR(fl validator.FieldLevel) bool {
	cidr := fl.Field().String()
	if cidr == "" {
		return true
	}
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

func validateCIDRSlice(fl validator.FieldLevel) bool {
	for _, cidr := range fl.Field().Interface().([]string) {
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return false
		}
	}
	return true
}

func validateIP(fl validator.FieldLevel) bool {
	ip := fl.Field().String()
	if ip == "" {
		return true
	}
	return net.ParseIP(ip) != nil
}

func validateIPSlice(fl validator.FieldLevel) bool {
	for _, ip := range fl.Field().Interface().([]string) {
		if ip == "" {
			continue
		}
		if net.ParseIP(ip) == nil {
			return false
		}
	}
	return true
}

func validatePort(fl validator.FieldLevel) bool {
	port := fl.Field().String()
	if port == "" {
		return true
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	return p > 0 && p <= 65535
}

func validatePortSlice(fl validator.FieldLevel) bool {
	for _, port := range fl.Field().Interface().([]string) {
		if port == "" {
			continue
		}
		p, err := strconv.Atoi(port)
		if err != nil || p <= 0 || p > 65535 {
			return false
		}
	}
	return true
}

func validateASN(fl validator.FieldLevel) bool {
	asn := strings.TrimPrefix(fl.Field().String(), "AS")
	asn = strings.TrimPrefix(asn, "as")
	if asn == "" {
		return true
	}
	_, err := strconv.Atoi(asn)
	return err == nil && len(asn) <= 10
}

func validateASNSlice(fl validator.FieldLevel) bool {
	for _, asn := range fl.Field().Interface().([]string) {
		asnTrim := strings.TrimPrefix(asn, "AS")
		asnTrim = strings.TrimPrefix(asnTrim, "as")
		if asnTrim == "" {
			continue
		}
		if _, err := strconv.Atoi(asnTrim); err != nil || len(asnTrim) > 10 {
			return false
		}
	}
	return true
}

func validateCountryCode(fl validator.FieldLevel) bool {
	code := fl.Field().String()
	if code == "" {
		return true
	}
	return countryCodeRegex.MatchString(code)
}

func validateCountryCodeSlice(fl validator.FieldLevel) bool {
	for _, code := range fl.Field().Interface().([]string) {
		if code == "" {
			continue
		}
		if !countryCodeRegex.MatchString(code) {
			return false
		}
	}
	return true
}

func validateDuration(fl validator.FieldLevel) bool {
	duration := fl.Field().String()
	if duration == "" {
		return true
	}
	_, err := time.ParseDuration(duration)
	return err == nil
}
