package internal

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

func NewValidator() *validator.Validate {
	v := validator.New()
	err := v.RegisterValidation("regexp", validateRegex)
	if err != nil {
		panic(err)
	}
	return v
}

func ValidateStruct(v *validator.Validate, s interface{}) error {
	err := v.Struct(s)
	if err != nil {
		return err
	}
	return nil
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
