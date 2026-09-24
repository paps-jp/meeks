package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
)

// language is a supported UI language. The landing page is served at "/"
// for the default language and at "/{code}" for the others.
type language struct {
	Code     string
	Name     string // native name, shown in the language switcher
	OGLocale string
	RTL      bool
}

const defaultLang = "ja"

// languages lists the supported languages in switcher order. Translations
// live in web/static/i18n/{code}.json and are shared with the browser client.
var languages = []language{
	{"ja", "日本語", "ja_JP", false},
	{"en", "English", "en_US", false},
	{"ko", "한국어", "ko_KR", false},
	{"zh", "中文", "zh_CN", false},
	{"ru", "Русский", "ru_RU", false},
	{"ar", "العربية", "ar_AR", true},
	{"hi", "हिन्दी", "hi_IN", false},
	{"es", "Español", "es_ES", false},
	{"bn", "বাংলা", "bn_BD", false},
	{"pt", "Português", "pt_BR", false},
	{"id", "Indonesia", "id_ID", false},
}

func findLanguage(code string) (language, bool) {
	for _, l := range languages {
		if l.Code == code {
			return l, true
		}
	}
	return language{}, false
}

// langPath is the landing page path for a language.
func langPath(code string) string {
	if code == defaultLang {
		return "/"
	}
	return "/" + code
}

// translations maps language code -> key -> text.
type translations map[string]map[string]string

func loadTranslations(static fs.FS) (translations, error) {
	tr := translations{}
	for _, l := range languages {
		b, err := fs.ReadFile(static, "i18n/"+l.Code+".json")
		if err != nil {
			return nil, err
		}
		m := map[string]string{}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("i18n/%s.json: %w", l.Code, err)
		}
		tr[l.Code] = m
	}
	return tr, nil
}

// text returns the translation, falling back to English, then the default
// language, then the key itself.
func (tr translations) text(code, key string) string {
	for _, c := range []string{code, "en", defaultLang} {
		if s, ok := tr[c][key]; ok {
			return s
		}
	}
	return key
}
