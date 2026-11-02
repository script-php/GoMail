package handlers

import (
	"bytes"
	stdhtml "html"
	"net/url"
	"strings"

	xhtml "golang.org/x/net/html"
)

var allowedEmailElements = map[string]bool{
	"a": true, "abbr": true, "address": true, "article": true, "aside": true, "b": true, "blockquote": true,
	"br": true, "caption": true, "center": true, "cite": true, "code": true, "col": true, "colgroup": true,
	"dd": true, "del": true, "details": true, "div": true, "dl": true, "dt": true, "em": true, "figcaption": true,
	"figure": true, "font": true, "h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true, "hr": true,
	"i": true, "img": true, "ins": true, "kbd": true, "li": true, "mark": true, "ol": true, "p": true, "pre": true,
	"q": true, "s": true, "samp": true, "small": true, "span": true, "strike": true, "strong": true, "sub": true,
	"summary": true, "sup": true, "table": true, "tbody": true, "td": true, "tfoot": true, "th": true, "thead": true,
	"tr": true, "tt": true, "u": true, "ul": true, "var": true,
}
var allowedEmailAttrs = map[string]bool{
	"abbr": true, "align": true, "alt": true, "aria-label": true, "bgcolor": true, "border": true, "cellpadding": true,
	"cellspacing": true, "class": true, "colspan": true, "dir": true, "height": true, "href": true, "lang": true,
	"role": true, "rowspan": true, "scope": true, "src": true, "style": true, "target": true, "title": true, "valign": true, "width": true,
}

// sanitizeHTML is a parser-based allowlist sanitizer. Unknown elements are
// unwrapped, active-content elements and their contents are dropped.
func sanitizeHTML(input string) string { return sanitizeHTMLWithRemoteImages(input, false) }

func sanitizeHTMLWithRemoteImages(input string, allowRemoteImages bool) string {
	root, err := xhtml.Parse(strings.NewReader(input))
	if err != nil {
		return ""
	}
	var out bytes.Buffer
	for child := root.FirstChild; child != nil; child = child.NextSibling {
		renderSafeEmailNode(&out, child, allowRemoteImages)
	}
	return strings.TrimSpace(out.String())
}

func renderSafeEmailNode(out *bytes.Buffer, n *xhtml.Node, allowRemoteImages bool) {
	if n.Type == xhtml.TextNode {
		out.WriteString(stdhtml.EscapeString(n.Data))
		return
	}
	if n.Type != xhtml.ElementNode {
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			renderSafeEmailNode(out, c, allowRemoteImages)
		}
		return
	}
	tag := strings.ToLower(n.Data)
	if tag == "script" || tag == "style" || tag == "iframe" || tag == "object" || tag == "embed" || tag == "form" || tag == "input" || tag == "button" || tag == "textarea" || tag == "select" || tag == "svg" || tag == "math" || tag == "template" {
		return
	}
	if !allowedEmailElements[tag] {
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			renderSafeEmailNode(out, c, allowRemoteImages)
		}
		return
	}
	out.WriteByte('<')
	out.WriteString(tag)
	for _, a := range n.Attr {
		key := strings.ToLower(a.Key)
		if !allowedEmailAttrs[key] || strings.HasPrefix(key, "on") {
			continue
		}
		value := a.Val
		if key == "href" || key == "src" {
			if !safeEmailURL(value, key == "src", allowRemoteImages) {
				continue
			}
		}
		if key == "style" {
			value = sanitizeInlineStyle(value)
			if value == "" {
				continue
			}
		}
		if key == "target" {
			value = "_blank"
		}
		out.WriteByte(' ')
		out.WriteString(key)
		out.WriteString(`="`)
		out.WriteString(stdhtml.EscapeString(value))
		out.WriteByte('"')
	}
	if tag == "a" {
		out.WriteString(` rel="noopener noreferrer nofollow"`)
	}
	out.WriteByte('>')
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		renderSafeEmailNode(out, c, allowRemoteImages)
	}
	if tag != "br" && tag != "hr" && tag != "img" && tag != "col" {
		out.WriteString("</")
		out.WriteString(tag)
		out.WriteByte('>')
	}
}

func safeEmailURL(raw string, image, allowRemoteImages bool) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		return false
	}
	if image {
		if scheme == "http" || scheme == "https" {
			return allowRemoteImages && u.Host != ""
		}
		if scheme == "cid" {
			return len(raw) <= 512 && u.Opaque != ""
		}
		if scheme == "data" {
			lower := strings.ToLower(raw)
			return len(raw) <= 64*1024 && (strings.HasPrefix(lower, "data:image/png;base64,") || strings.HasPrefix(lower, "data:image/jpeg;base64,") || strings.HasPrefix(lower, "data:image/gif;base64,") || strings.HasPrefix(lower, "data:image/webp;base64,"))
		}
		return false
	}
	return scheme == "http" || scheme == "https" || scheme == "mailto"
}
func sanitizeInlineStyle(s string) string {
	lower := strings.ToLower(s)
	forbidden := []string{"url(", "expression(", "@import", "javascript:", "behavior:", "-moz-binding"}
	for _, x := range forbidden {
		if strings.Contains(lower, x) {
			return ""
		}
	}
	return s
}
