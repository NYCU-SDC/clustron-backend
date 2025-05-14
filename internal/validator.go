package internal

import "github.com/go-playground/validator/v10"

func NewValidator() *validator.Validate {
	return validator.New()
}

func ValidateStruct(v *validator.Validate, s interface{}) error {
	err := v.Struct(s)
	if err != nil {
		return err
	}
	return nil
}
