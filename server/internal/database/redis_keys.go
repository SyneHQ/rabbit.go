package database

import "errors"

// Empty prefixes retain the keys used by existing installations.
func validateRedisKeyPrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	invalid := errors.New("invalid RABBIT_REDIS_KEY_PREFIX: use 2 to 128 ASCII letters, digits, colons, underscores, or hyphens. Start with a letter or digit. End with a colon")
	alphanumeric := func(b byte) bool {
		return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
	}
	if len(prefix) < 2 || len(prefix) > 128 || !alphanumeric(prefix[0]) || prefix[len(prefix)-1] != ':' {
		return invalid
	}
	for i := range len(prefix) {
		b := prefix[i]
		if !alphanumeric(b) && b != ':' && b != '_' && b != '-' {
			return invalid
		}
	}
	return nil
}

// Each command receives one prefixed key, including keys passed to Lua scripts.
func (d *Database) redisKey(key string) string { return d.redisKeyPrefix + key }
