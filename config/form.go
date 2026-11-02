package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"strconv"
	"strings"
)

// FormField describes one leaf of the editable configuration. Lists use JSON
// syntax in their individual fields so their element types remain unambiguous.
type FormField struct {
	Path, Label, Value, Kind string
	Secret                   bool
}

type FormSection struct {
	Name, Label string
	Fields      []FormField
}

func EditableFormSections(editable []byte) ([]FormSection, error) {
	var cfg Config
	if err := json.Unmarshal(editable, &cfg); err != nil {
		return nil, err
	}
	value := reflect.ValueOf(cfg)
	typeInfo := value.Type()
	sections := make([]FormSection, 0, value.NumField())
	for i := 0; i < value.NumField(); i++ {
		name := typeInfo.Field(i).Tag.Get("json")
		section := FormSection{Name: name, Label: formLabel(name)}
		appendFormFields(&section.Fields, value.Field(i), []string{name}, nil)
		sections = append(sections, section)
	}
	return sections, nil
}

func appendFormFields(fields *[]FormField, value reflect.Value, path, label []string) {
	if value.Kind() == reflect.Struct {
		typeInfo := value.Type()
		for i := 0; i < value.NumField(); i++ {
			name := typeInfo.Field(i).Tag.Get("json")
			appendFormFields(fields, value.Field(i), append(append([]string(nil), path...), name), append(append([]string(nil), label...), formLabel(name)))
		}
		return
	}
	field := FormField{Path: strings.Join(path, "."), Label: strings.Join(label, " · ")}
	switch value.Kind() {
	case reflect.String:
		field.Kind = "text"
		field.Value = value.String()
		if field.Value == SecretPlaceholder {
			field.Secret = true
			field.Value = ""
		}
	case reflect.Bool:
		field.Kind = "bool"
		field.Value = strconv.FormatBool(value.Bool())
	case reflect.Pointer:
		field.Kind = "nullable_bool"
		field.Value = "default"
		if !value.IsNil() {
			field.Value = strconv.FormatBool(value.Elem().Bool())
		}
	case reflect.Int, reflect.Int64:
		field.Kind = "number"
		field.Value = strconv.FormatInt(value.Int(), 10)
	case reflect.Slice:
		field.Kind = "list"
		encoded, _ := json.Marshal(value.Interface())
		field.Value = string(encoded)
	}
	*fields = append(*fields, field)
}

func formLabel(name string) string {
	return strings.ToUpper(name[:1]) + strings.ReplaceAll(name[1:], "_", " ")
}

// ParseEditableForm applies a complete, typed form to the redacted current
// document and then uses the same secret-preserving validation as JSON mode.
func ParseEditableForm(values url.Values, current *Config) (*Config, error) {
	editable, err := EditableJSON(current)
	if err != nil {
		return nil, err
	}
	sections, err := EditableFormSections(editable)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(editable))
	decoder.UseNumber()
	var document map[string]interface{}
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	allowed := make(map[string]bool)
	for _, section := range sections {
		for _, field := range section.Fields {
			key := "field." + field.Path
			allowed[key] = true
			posted := values[key]
			if len(posted) != 1 {
				return nil, fmt.Errorf("missing or repeated field %s", field.Path)
			}
			value, err := parseFormField(field, posted[0])
			if err != nil {
				return nil, fmt.Errorf("%s: %w", field.Path, err)
			}
			parts := strings.Split(field.Path, ".")
			parent := document
			for _, part := range parts[:len(parts)-1] {
				parent = parent[part].(map[string]interface{})
			}
			parent[parts[len(parts)-1]] = value
		}
	}
	for key := range values {
		if strings.HasPrefix(key, "field.") && !allowed[key] {
			return nil, fmt.Errorf("unknown form field %s", key)
		}
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	return ParseEditableJSON(encoded, current)
}

func parseFormField(field FormField, raw string) (interface{}, error) {
	switch field.Kind {
	case "text":
		if field.Secret && raw == "" {
			return SecretPlaceholder, nil
		}
		return raw, nil
	case "bool", "nullable_bool":
		if field.Kind == "nullable_bool" && raw == "default" {
			return nil, nil
		}
		return strconv.ParseBool(raw)
	case "number":
		if _, err := strconv.ParseInt(raw, 10, 64); err != nil {
			return nil, fmt.Errorf("enter a whole number: %w", err)
		}
		return json.Number(raw), nil
	case "list":
		decoder := json.NewDecoder(strings.NewReader(raw))
		var value interface{}
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("enter a JSON list: %w", err)
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			return nil, fmt.Errorf("enter one JSON list")
		}
		if value != nil && reflect.ValueOf(value).Kind() != reflect.Slice {
			return nil, fmt.Errorf("enter a JSON list")
		}
		return value, nil
	}
	return nil, fmt.Errorf("unsupported field type")
}
