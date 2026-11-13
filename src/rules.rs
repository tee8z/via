use crate::config::{RestCommandConfig, RestRuleConfig, RuleEffect};
use crate::error::ViaError;

// Method and path rules for one REST capability.
//
// Evaluation order for a request:
//   1. The request path must already be in normal form.
//   2. `methods`, when set, must contain the request method.
//   3. A match in `deny_paths`, or in a `rules` entry with `effect = "deny"`,
//      refuses the request.
//   4. When `allow_paths` or any `rules` entry with `effect = "allow"` exists,
//      the request must match at least one of them.
pub(crate) struct RestRules {
    methods: Option<Vec<String>>,
    allow_paths: Vec<PathPattern>,
    deny_paths: Vec<PathPattern>,
    rules: Vec<Rule>,
}

struct Rule {
    methods: Option<Vec<String>>,
    path: PathPattern,
    effect: RuleEffect,
}

impl Rule {
    fn applies(&self, method: &str, path: &RequestPath) -> bool {
        self.methods
            .as_ref()
            .is_none_or(|methods| methods.iter().any(|allowed| allowed == method))
            && self.path.matches(path)
    }
}

impl RestRules {
    // Returns `None` when the capability configures no rule field. The error
    // completes a sentence that names the capability.
    pub(crate) fn from_config(config: &RestCommandConfig) -> Result<Option<Self>, String> {
        if !config.has_rules() {
            return Ok(None);
        }

        let methods = config
            .methods
            .as_deref()
            .map(|methods| normalize_methods(methods, "methods"))
            .transpose()?;
        let allow_paths = parse_patterns(&config.allow_paths, "allow_paths")?;
        let deny_paths = parse_patterns(&config.deny_paths, "deny_paths")?;
        let mut rules = Vec::with_capacity(config.rules.len());
        for rule in &config.rules {
            rules.push(Rule {
                methods: rule
                    .methods
                    .as_deref()
                    .map(|methods| normalize_methods(methods, "rules"))
                    .transpose()?,
                path: parse_pattern(&rule.path, "rules")?,
                effect: rule.effect,
            });
        }

        Ok(Some(Self {
            methods,
            allow_paths,
            deny_paths,
            rules,
        }))
    }

    // `raw_path` is the path component of the request target: no query
    // string and no fragment.
    pub(crate) fn check(&self, method: &str, raw_path: &str) -> Result<(), ViaError> {
        let method = method.to_ascii_uppercase();
        let path = RequestPath::parse(raw_path)
            .map_err(|problem| refused("path_not_normalized", problem))?;

        if let Some(methods) = &self.methods {
            if !methods.contains(&method) {
                return Err(refused(
                    "method_not_allowed",
                    &format!("method `{method}` is not allowed"),
                ));
            }
        }

        let denied = self.deny_paths.iter().any(|pattern| pattern.matches(&path))
            || self
                .rules
                .iter()
                .any(|rule| rule.effect == RuleEffect::Deny && rule.applies(&method, &path));
        if denied {
            return Err(refused("path_denied", "the path is denied"));
        }

        let has_allow_list = !self.allow_paths.is_empty()
            || self
                .rules
                .iter()
                .any(|rule| rule.effect == RuleEffect::Allow);
        if !has_allow_list {
            return Ok(());
        }

        let allowed = self
            .allow_paths
            .iter()
            .any(|pattern| pattern.matches(&path))
            || self
                .rules
                .iter()
                .any(|rule| rule.effect == RuleEffect::Allow && rule.applies(&method, &path));
        if allowed {
            Ok(())
        } else {
            Err(refused(
                "path_not_allowed",
                "the method and path are not in the allow list",
            ))
        }
    }
}

pub(crate) fn refused(reason: &'static str, problem: &str) -> ViaError {
    ViaError::denied(
        reason,
        format!("request refused by capability rules: {problem}"),
    )
}

// A compact, human-readable form such as `allow POST,PATCH /repos/*/*/issues`.
pub(crate) fn describe_rule(rule: &RestRuleConfig) -> String {
    let effect = match rule.effect {
        RuleEffect::Allow => "allow",
        RuleEffect::Deny => "deny",
    };
    let methods = match &rule.methods {
        Some(methods) => methods.join(","),
        None => "ANY".to_owned(),
    };
    format!("{effect} {methods} {}", rule.path)
}

fn normalize_methods(methods: &[String], field: &str) -> Result<Vec<String>, String> {
    if methods.is_empty() {
        return Err(format!(
            "{field} must list at least one HTTP method when methods is set"
        ));
    }

    methods
        .iter()
        .map(|method| {
            let normalized = method.to_ascii_uppercase();
            let valid = !normalized.is_empty()
                && normalized
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b'-');
            if valid {
                Ok(normalized)
            } else {
                Err(format!("has invalid HTTP method `{method}` in {field}"))
            }
        })
        .collect()
}

fn parse_patterns(patterns: &[String], field: &str) -> Result<Vec<PathPattern>, String> {
    patterns
        .iter()
        .map(|pattern| parse_pattern(pattern, field))
        .collect()
}

fn parse_pattern(pattern: &str, field: &str) -> Result<PathPattern, String> {
    PathPattern::parse(pattern)
        .map_err(|problem| format!("has invalid path pattern `{pattern}` in {field}: {problem}"))
}

#[derive(Debug, PartialEq, Eq)]
enum PatternSegment {
    Literal(String),
    AnySegment,
    Rest,
}

// `/`-separated segments. `*` matches exactly one segment. `**` is only valid
// as the last segment and matches the rest of the path, including nothing.
// Every other segment is a literal.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PathPattern {
    segments: Vec<PatternSegment>,
}

impl PathPattern {
    pub(crate) fn parse(pattern: &str) -> Result<Self, &'static str> {
        let Some(body) = pattern.strip_prefix('/') else {
            return Err("a pattern must start with `/`");
        };
        if pattern.contains('\\') || pattern.chars().any(char::is_control) {
            return Err("a pattern may not contain a backslash or a control character");
        }
        if body.is_empty() {
            return Ok(Self {
                segments: Vec::new(),
            });
        }

        // One trailing slash is not significant.
        let body = body.strip_suffix('/').unwrap_or(body);
        let parts = body.split('/').collect::<Vec<_>>();
        let mut segments = Vec::with_capacity(parts.len());
        for (index, part) in parts.iter().enumerate() {
            let segment = match *part {
                "" => return Err("a pattern may not contain an empty segment"),
                "." | ".." => return Err("a pattern may not contain a `.` or `..` segment"),
                "*" => PatternSegment::AnySegment,
                "**" if index + 1 == parts.len() => PatternSegment::Rest,
                "**" => return Err("`**` is only valid as the last segment"),
                literal if literal.contains('*') => {
                    return Err("`*` and `**` must be whole segments");
                }
                literal => PatternSegment::Literal(literal.to_owned()),
            };
            segments.push(segment);
        }

        Ok(Self { segments })
    }

    pub(crate) fn matches(&self, path: &RequestPath) -> bool {
        for (index, segment) in self.segments.iter().enumerate() {
            let candidate = path.segments.get(index).map(Vec::as_slice);
            match segment {
                PatternSegment::Rest => return true,
                PatternSegment::AnySegment => {
                    if candidate.is_none() {
                        return false;
                    }
                }
                PatternSegment::Literal(literal) => {
                    if candidate != Some(literal.as_bytes()) {
                        return false;
                    }
                }
            }
        }

        self.segments.len() == path.segments.len()
    }
}

// A request path split into percent-decoded segments. Parsing refuses every
// form that an HTTP client or server could normalize into a different path.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RequestPath {
    segments: Vec<Vec<u8>>,
}

impl RequestPath {
    pub(crate) fn parse(raw: &str) -> Result<Self, &'static str> {
        let Some(body) = raw.strip_prefix('/') else {
            return Err("the path must start with `/`");
        };
        check_raw_target(raw)?;
        if raw.contains(['?', '#']) {
            return Err("the path contains `?` or `#`");
        }
        if body.is_empty() {
            return Ok(Self {
                segments: Vec::new(),
            });
        }

        // One trailing slash is not significant.
        let body = body.strip_suffix('/').unwrap_or(body);
        let mut segments = Vec::new();
        for part in body.split('/') {
            if part.is_empty() {
                return Err("the path contains an empty segment (`//`)");
            }
            let Some(decoded) = percent_decode(part) else {
                return Err("the path contains malformed percent-encoding");
            };
            if decoded == b"." || decoded == b".." {
                return Err("the path contains a `.` or `..` segment");
            }
            if decoded.contains(&b'/') || decoded.contains(&b'\\') {
                return Err("the path contains an encoded slash or backslash");
            }
            if decoded.iter().any(u8::is_ascii_control) {
                return Err("the path contains an encoded control character");
            }
            segments.push(decoded);
        }

        Ok(Self { segments })
    }
}

// Characters that URL parsers strip or rewrite. They are refused anywhere in
// a request target, including its query string.
pub(crate) fn check_raw_target(target: &str) -> Result<(), &'static str> {
    if target.contains('\\') {
        return Err("the request target contains a backslash");
    }
    if target
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(
            "the request target contains whitespace or a control character; percent-encode it",
        );
    }

    Ok(())
}

// Strict decoding: `None` when a `%` is not followed by two hex digits.
pub(crate) fn percent_decode(value: &str) -> Option<Vec<u8>> {
    decode(value, true)
}

// Lenient decoding keeps a malformed `%` sequence as literal bytes.
pub(crate) fn percent_decode_lenient(value: &str) -> Vec<u8> {
    decode(value, false).unwrap_or_default()
}

fn decode(value: &str, strict: bool) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if let Some(escaped) = decode_escape(bytes.get(index + 1), bytes.get(index + 2)) {
                decoded.push(escaped);
                index += 3;
                continue;
            }
            if strict {
                return None;
            }
        }
        decoded.push(byte);
        index += 1;
    }

    Some(decoded)
}

fn decode_escape(high: Option<&u8>, low: Option<&u8>) -> Option<u8> {
    let high = hex_value(*high?)?;
    let low = hex_value(*low?)?;
    Some((high << 4) | low)
}

fn hex_value(byte: u8) -> Option<u8> {
    char::from(byte)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(raw: &str) -> RestRules {
        let config: RestCommandConfig =
            toml::from_str(&format!("base_url = \"https://api.example.com\"\n{raw}")).unwrap();
        RestRules::from_config(&config)
            .unwrap()
            .expect("the test config sets a rule field")
    }

    fn rules_error(raw: &str) -> String {
        let config: RestCommandConfig =
            toml::from_str(&format!("base_url = \"https://api.example.com\"\n{raw}")).unwrap();
        match RestRules::from_config(&config) {
            Ok(_) => panic!("expected the rules to be rejected"),
            Err(problem) => problem,
        }
    }

    fn denial(rules: &RestRules, method: &str, path: &str) -> &'static str {
        match rules.check(method, path) {
            Err(ViaError::Denied { reason, .. }) => reason,
            Err(error) => panic!("expected a denial for {method} {path}, got {error}"),
            Ok(()) => panic!("expected a denial for {method} {path}"),
        }
    }

    fn matches(pattern: &str, path: &str) -> bool {
        PathPattern::parse(pattern)
            .unwrap()
            .matches(&RequestPath::parse(path).unwrap())
    }

    #[test]
    fn capabilities_without_rule_fields_have_no_rules() {
        let config: RestCommandConfig =
            toml::from_str("base_url = \"https://api.example.com\"").unwrap();

        assert!(RestRules::from_config(&config).unwrap().is_none());
    }

    #[test]
    fn literal_segments_match_exactly() {
        assert!(matches("/user", "/user"));
        assert!(matches("/repos/owner/repo", "/repos/owner/repo"));
        assert!(!matches("/user", "/users"));
        assert!(!matches("/user", "/user/keys"));
        assert!(!matches("/user/keys", "/user"));
        assert!(!matches("/User", "/user"));
        assert!(matches("/", "/"));
        assert!(!matches("/", "/user"));
    }

    #[test]
    fn single_star_matches_exactly_one_segment() {
        assert!(matches("/repos/*/issues", "/repos/owner/issues"));
        assert!(!matches("/repos/*/issues", "/repos/issues"));
        assert!(!matches("/repos/*/issues", "/repos/owner/repo/issues"));
        assert!(matches("/repos/*/*", "/repos/owner/repo"));
        assert!(!matches("/repos/*/*", "/repos/owner"));
        assert!(!matches("/*", "/"));
    }

    #[test]
    fn double_star_matches_the_rest_including_nothing() {
        assert!(matches("/repos/owner/**", "/repos/owner"));
        assert!(matches("/repos/owner/**", "/repos/owner/repo"));
        assert!(matches("/repos/owner/**", "/repos/owner/repo/issues/1"));
        assert!(!matches("/repos/owner/**", "/repos/other/repo"));
        assert!(!matches("/repos/owner/**", "/repos/owner-two/repo"));
        assert!(matches("/**", "/"));
        assert!(matches("/**", "/anything/at/all"));
        assert!(matches(
            "/repos/*/*/actions/secrets/**",
            "/repos/o/r/actions/secrets"
        ));
        assert!(matches(
            "/repos/*/*/actions/secrets/**",
            "/repos/o/r/actions/secrets/NAME"
        ));
    }

    #[test]
    fn literals_compare_after_percent_decoding_the_request() {
        assert!(matches("/repos/owner/repo", "/repos/%6fwner/repo"));
        assert!(matches("/files/a b", "/files/a%20b"));
        assert!(matches("/files/100%", "/files/100%25"));
        assert!(!matches("/files/%61", "/files/%61"));
        assert!(matches("/files/%61", "/files/%2561"));
        assert!(matches("/files/caf\u{e9}", "/files/caf%C3%A9"));
        assert!(matches("/files/caf\u{e9}", "/files/caf\u{e9}"));
    }

    #[test]
    fn one_trailing_slash_is_not_significant() {
        assert!(matches("/admin", "/admin/"));
        assert!(matches("/admin/", "/admin"));
        assert!(matches("/admin/**", "/admin/"));
        assert!(!matches("/admin/*", "/admin/"));
    }

    #[test]
    fn rejects_invalid_patterns() {
        for pattern in [
            "", "user", "//", "/a//b", "/a/./b", "/a/../b", "/a/**/b", "/a/b*", "/a/*b/c",
            "/a/***", "/a\\b", "/a\nb",
        ] {
            assert!(
                PathPattern::parse(pattern).is_err(),
                "expected pattern `{pattern}` to be rejected"
            );
        }
    }

    #[test]
    fn rejects_paths_that_are_not_in_normal_form() {
        for path in [
            "user",
            "",
            "/a/../b",
            "/a/./b",
            "/a/..",
            "/..",
            "/a/%2e%2e/b",
            "/a/%2E%2E/b",
            "/a/.%2e/b",
            "/a/%2e./b",
            "/a/%2e/b",
            "//",
            "//a",
            "/a//b",
            "/a/b//",
            "/a\\b",
            "/a/%2f/b",
            "/a/b%2Fc",
            "/a/%5c/b",
            "/a/b%5Cc",
            "/a/b%00c",
            "/a/b%0ac",
            "/a/b%7fc",
            "/a/b\tc",
            "/a/b\nc",
            "/a/b c",
            "/a/b ",
            "/a/b\u{a0}c",
            "/a/%zz",
            "/a/%2",
            "/a/%",
            "/a?b=c",
            "/a#b",
        ] {
            assert!(
                RequestPath::parse(path).is_err(),
                "expected path `{path}` to be rejected"
            );
        }
    }

    #[test]
    fn accepts_paths_in_normal_form() {
        for path in [
            "/",
            "/user",
            "/user/",
            "/repos/owner/repo/issues/1",
            "/files/a%20b",
            "/files/..hidden",
            "/files/a..b",
            "/files/...",
            "/files/%2e%2e%2e",
            "/files/caf\u{e9}",
            "/a/b;c=d",
            "/a/b:c",
            "/a/@b",
        ] {
            assert!(
                RequestPath::parse(path).is_ok(),
                "expected path `{path}` to be accepted"
            );
        }
    }

    #[test]
    fn decodes_percent_escapes() {
        assert_eq!(percent_decode("a%20b%2F").unwrap(), b"a b/");
        assert_eq!(percent_decode("%C3%a9").unwrap(), [0xc3_u8, 0xa9]);
        assert_eq!(percent_decode("plain").unwrap(), b"plain");
        assert!(percent_decode("%").is_none());
        assert!(percent_decode("%4").is_none());
        assert!(percent_decode("%g0").is_none());
        assert_eq!(percent_decode_lenient("100%"), b"100%");
        assert_eq!(percent_decode_lenient("%zz%41"), b"%zzA");
    }

    #[test]
    fn methods_are_compared_without_case() {
        let rules = rules("methods = [\"get\", \"Post\"]");

        assert!(rules.check("GET", "/user").is_ok());
        assert!(rules.check("get", "/user").is_ok());
        assert!(rules.check("POST", "/user").is_ok());
        assert_eq!(denial(&rules, "DELETE", "/user"), "method_not_allowed");
        assert_eq!(denial(&rules, "delete", "/user"), "method_not_allowed");
        assert_eq!(denial(&rules, "PATCH", "/user"), "method_not_allowed");
    }

    #[test]
    fn allow_paths_require_a_match() {
        let rules = rules("allow_paths = [\"/repos/owner/**\", \"/user\"]");

        assert!(rules.check("GET", "/user").is_ok());
        assert!(rules.check("DELETE", "/repos/owner/repo").is_ok());
        assert_eq!(denial(&rules, "GET", "/users"), "path_not_allowed");
        assert_eq!(
            denial(&rules, "GET", "/repos/other/repo"),
            "path_not_allowed"
        );
        assert_eq!(denial(&rules, "GET", "/"), "path_not_allowed");
    }

    #[test]
    fn deny_paths_win_over_allow_paths() {
        let rules = rules(
            "allow_paths = [\"/repos/owner/**\"]\ndeny_paths = [\"/repos/*/*/actions/secrets/**\"]",
        );

        assert!(rules.check("GET", "/repos/owner/repo/issues").is_ok());
        assert_eq!(
            denial(&rules, "GET", "/repos/owner/repo/actions/secrets"),
            "path_denied"
        );
        assert_eq!(
            denial(&rules, "PUT", "/repos/owner/repo/actions/secrets/NAME"),
            "path_denied"
        );
        assert_eq!(
            denial(&rules, "GET", "/repos/owner/repo/actions/secrets/"),
            "path_denied"
        );
        assert_eq!(
            denial(&rules, "GET", "/repos/owner/repo/actions/%73ecrets/NAME"),
            "path_denied"
        );
    }

    #[test]
    fn deny_paths_alone_leave_other_paths_open() {
        let rules = rules("deny_paths = [\"/admin/**\"]");

        assert!(rules.check("GET", "/user").is_ok());
        assert_eq!(denial(&rules, "GET", "/admin"), "path_denied");
        assert_eq!(denial(&rules, "GET", "/admin/users"), "path_denied");
    }

    #[test]
    fn bypass_attempts_are_refused_before_matching() {
        let rules = rules("allow_paths = [\"/public/**\"]\ndeny_paths = [\"/admin/**\"]");

        for path in [
            "/public/../admin",
            "/public/%2e%2e/admin",
            "/public/%2E%2e/admin",
            "/public/.%2e/admin",
            "/public//admin",
            "//admin",
            "/public/%2f../admin",
            "/public/..%2fadmin",
            "/public\\..\\admin",
            "/public/%5c..%5cadmin",
            "/public/./../admin",
            "/public/\tadmin",
            "/public/%0d%0aadmin",
        ] {
            assert_eq!(
                denial(&rules, "GET", path),
                "path_not_normalized",
                "path `{path}`"
            );
        }
    }

    #[test]
    fn fine_rules_combine_methods_and_paths() {
        let rules = rules(
            r#"
methods = ["GET", "POST", "DELETE"]
allow_paths = ["/user"]

[[rules]]
methods = ["get"]
path = "/repos/owner/**"
effect = "allow"

[[rules]]
methods = ["POST"]
path = "/repos/owner/repo/issues/**"
effect = "allow"

[[rules]]
path = "/repos/owner/repo/keys/**"
effect = "deny"

[[rules]]
methods = ["DELETE"]
path = "/user"
effect = "deny"
"#,
        );

        assert!(rules.check("GET", "/user").is_ok());
        assert!(rules.check("POST", "/user").is_ok());
        assert_eq!(denial(&rules, "DELETE", "/user"), "path_denied");
        assert!(rules.check("GET", "/repos/owner/repo/pulls").is_ok());
        assert_eq!(
            denial(&rules, "POST", "/repos/owner/repo/pulls"),
            "path_not_allowed"
        );
        assert!(rules.check("POST", "/repos/owner/repo/issues").is_ok());
        assert!(rules
            .check("post", "/repos/owner/repo/issues/1/comments")
            .is_ok());
        assert_eq!(
            denial(&rules, "GET", "/repos/owner/repo/keys"),
            "path_denied"
        );
        assert_eq!(
            denial(&rules, "PATCH", "/repos/owner/repo/issues/1"),
            "method_not_allowed"
        );
    }

    #[test]
    fn deny_rules_alone_do_not_create_an_allow_list() {
        let rules = rules("[[rules]]\nmethods = [\"DELETE\"]\npath = \"/**\"\neffect = \"deny\"");

        assert!(rules.check("GET", "/anything").is_ok());
        assert_eq!(denial(&rules, "DELETE", "/anything"), "path_denied");
    }

    #[test]
    fn rejects_invalid_rule_configuration() {
        assert!(rules_error("methods = []").contains("at least one HTTP method"));
        assert!(rules_error("methods = [\"GE T\"]").contains("invalid HTTP method `GE T`"));
        assert!(rules_error("methods = [\"\"]").contains("invalid HTTP method"));
        assert!(rules_error("allow_paths = [\"user\"]")
            .contains("invalid path pattern `user` in allow_paths"));
        assert!(rules_error("deny_paths = [\"/a/**/b\"]")
            .contains("invalid path pattern `/a/**/b` in deny_paths"));
        assert!(
            rules_error("[[rules]]\npath = \"/a/b*\"\neffect = \"allow\"")
                .contains("invalid path pattern `/a/b*` in rules")
        );
        assert!(
            rules_error("[[rules]]\nmethods = []\npath = \"/a\"\neffect = \"allow\"")
                .contains("at least one HTTP method")
        );
    }

    #[test]
    fn describes_rules_compactly() {
        let config: RestCommandConfig = toml::from_str(
            r#"
base_url = "https://api.example.com"

[[rules]]
methods = ["post", "PATCH"]
path = "/repos/*/*/issues/**"
effect = "allow"

[[rules]]
path = "/admin/**"
effect = "deny"
"#,
        )
        .unwrap();

        assert_eq!(
            describe_rule(&config.rules[0]),
            "allow POST,PATCH /repos/*/*/issues/**"
        );
        assert_eq!(describe_rule(&config.rules[1]), "deny ANY /admin/**");
    }
}
