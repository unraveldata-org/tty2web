package utils

import (
	"log"
	"os"
	"reflect"
	"strings"

	"github.com/fatih/structs"
	"github.com/hashicorp/hcl"
	"github.com/urfave/cli/v2"

	"github.com/kost/tty2web/pkg/homedir"
)

func GenerateFlags(options ...interface{}) (flags []cli.Flag, mappings map[string]string, err error) {
	mappings = make(map[string]string)

	for _, struct_ := range options {
		o := structs.New(struct_)
		for _, field := range o.Fields() {
			alias := []string{}
			flagName := field.Tag("flagName")
			if flagName == "" {
				continue
			}
			envName := "TTY2WEB_" + strings.ToUpper(strings.Join(strings.Split(flagName, "-"), "_"))
			mappings[flagName] = field.Name()

			flagShortName := field.Tag("flagSName")
			if flagShortName != "" {
				alias = []string{flagShortName}
			}

			flagDescription := field.Tag("flagDescribe")

			switch field.Kind() {
			case reflect.String:
				flags = append(flags, &cli.StringFlag{
					Name:    flagName,
					Value:   field.Value().(string),
					Usage:   flagDescription,
					Aliases: alias,
					EnvVars: []string{envName},
				})
			case reflect.Bool:
				flags = append(flags, &cli.BoolFlag{
					Name:    flagName,
					Usage:   flagDescription,
					Aliases: alias,
					EnvVars: []string{envName},
				})
			case reflect.Int:
				flags = append(flags, &cli.IntFlag{
					Name:    flagName,
					Value:   field.Value().(int),
					Usage:   flagDescription,
					Aliases: alias,
					EnvVars: []string{envName},
				})
			case reflect.Float64:
				flags = append(flags, &cli.Float64Flag{
					Name:    flagName,
					Value:   field.Value().(float64),
					Usage:   flagDescription,
					Aliases: alias,
					EnvVars: []string{envName},
				})
			case reflect.Slice:
				// Handle slice type fields
				if _, ok := field.Value().([]string); !ok {
					log.Println("Warning: field ", field.Name(), " is a slice but not of type []string, skipping flag generation")
					continue
				}
				flags = append(flags, &cli.StringSliceFlag{
					Name:    flagName,
					Usage:   flagDescription,
					Aliases: alias,
					Action: func(c *cli.Context, i []string) error {
						log.Println(flagName + ": " + strings.Join(c.StringSlice(flagName), `, `))
						err := field.Set(i)
						if err != nil {
							return err
						}
						return nil
					},
					EnvVars: []string{envName},
				})

			}
		}
	}

	return
}

func ApplyFlags(
	flags []cli.Flag,
	mappingHint map[string]string,
	c *cli.Context,
	options ...interface{},
) {
	objects := make([]*structs.Struct, len(options))
	for i, struct_ := range options {
		objects[i] = structs.New(struct_)
	}

	for flagName, fieldName := range mappingHint {
		if !c.IsSet(flagName) {
			continue
		}
		var field *structs.Field
		var ok bool
		for _, o := range objects {
			field, ok = o.FieldOk(fieldName)
			if ok {
				break
			}
		}
		if field == nil {
			continue
		}
		var val interface{}
		switch field.Kind() {
		case reflect.String:
			val = c.String(flagName)
		case reflect.Bool:
			val = c.Bool(flagName)
		case reflect.Int:
			val = c.Int(flagName)
		}
		err := field.Set(val)
		if err != nil {
			continue
		}
	}
}

func ApplyConfigFile(filePath string, options ...interface{}) error {
	filePath = homedir.Expand(filePath)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return err
	}

	fileString := []byte{}
	log.Printf("Loading config file at: %s", filePath)
	fileString, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	for _, object := range options {
		if err := hcl.Decode(object, string(fileString)); err != nil {
			return err
		}
	}

	return nil
}
