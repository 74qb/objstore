package azure

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

/*
Shared Key Authorization Workflow
Request Construction:

Each HTTP request to Azure Blob Storage must include specific headers, such as:
x-ms-date: The current UTC date and time.
x-ms-version: The Azure Storage API version being used.
If the request includes metadata or other custom headers, they must also be included in the signature.
String-to-Sign:

A String-to-Sign is constructed from the HTTP method, headers, and other request details. This string represents the request in a canonical format.
The format of the String-to-Sign is defined by Azure Blob Storage and includes fields like:
HTTP method (e.g., GET, PUT, DELETE).
Canonicalized headers (e.g., x-ms-* headers).
Canonicalized resource (e.g., the container or blob path).


HMAC Signature:

The String-to-Sign is hashed using HMAC-SHA256 with the access key as the secret.
The resulting hash is Base64-encoded to produce the Authorization header.
Authorization Header:

Authorization: SharedKey <AccountName>:<Signature>


The computed signature is included in the Authorization header of the request in the following format:
<AccountName> is the name of your Azure Storage account.
<Signature> is the Base64-encoded HMAC-SHA256 hash.
Request Validation:

When Azure Blob Storage receives the request, it reconstructs the String-to-Sign and computes its own HMAC using the stored access key.
If the computed signature matches the one in the Authorization header, the request is authenticated.
*/

const (
	HeaderAuthorization     = "Authorization"
	HeaderXmsDate           = "x-ms-date"
	HeaderContentLength     = "Content-Length"
	HeaderContentEncoding   = "Content-Encoding"
	HeaderContentLanguage   = "Content-Language"
	HeaderContentType       = "Content-Type"
	HeaderContentMD5        = "Content-MD5"
	HeaderIfModifiedSince   = "If-Modified-Since"
	HeaderIfMatch           = "If-Match"
	HeaderIfNoneMatch       = "If-None-Match"
	HeaderIfUnmodifiedSince = "If-Unmodified-Since"
	HeaderRange             = "Range"
	HeaderXmsVersion        = "x-ms-version"
	HeaderXmsRequestID      = "x-ms-request-id"
)

type sharedKey struct {
	accountName string
	accountKey  []byte
}

func (k *sharedKey) sign(message string) (string, error) {
	h := hmac.New(sha256.New, k.accountKey)
	_, err := h.Write([]byte(message))
	if err != nil {
		return "", fmt.Errorf("failed to compute HMAC: %w", err)
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

func (k *sharedKey) buildStringToSign(req *fasthttp.Request) (string, error) {
	// https://docs.microsoft.com/en-us/rest/api/storageservices/authentication-for-the-azure-storage-services
	contentLength := header(HeaderContentLength, req)
	if contentLength == "0" {
		contentLength = ""
	}
	parsedURL, err := url.Parse(req.URI().String())
	if err != nil {
		return "", fmt.Errorf("Error parsing URL:", err)
	}

	canonicalizedResource, err := canonicalizedResource(k.accountName, parsedURL)
	if err != nil {
		return "", err
	}

	return strings.Join([]string{
		string(req.Header.Method()),
		header(HeaderContentEncoding, req),
		header(HeaderContentLanguage, req),
		contentLength,
		header(HeaderContentMD5, req),
		header(HeaderContentType, req),
		"", // Empty date because x-ms-date is expected (as per web page above)
		header(HeaderIfModifiedSince, req),
		header(HeaderIfMatch, req),
		header(HeaderIfNoneMatch, req),
		header(HeaderIfUnmodifiedSince, req),
		header(HeaderRange, req),
		canonicalizedHeader(req),
		canonicalizedResource,
	}, "\n"), nil
}

// Helper function to sign requests
func (k *sharedKey) SignRequest(req *fasthttp.Request) error {
	// Add required headers for Azure Blob Storage.
	req.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))
	req.Header.Set("x-ms-version", "2020-10-02")

	//https://github.com/Azure/azure-sdk-for-go/blob/043e772b9f0e0c48752f6fab76453c1aebbf3371/sdk/storage/azblob/sas/service.go#L54
	stringToSign, err := k.buildStringToSign(req)
	if err != nil {
		return fmt.Errorf("failed to build string to be signed: %w", err)
	}
	signature, err := k.sign(stringToSign)
	if err != nil {
		return fmt.Errorf("failed to compute HMAC: %w", err)
	}
	// Set the Authorization header
	req.Header.Set("Authorization", fmt.Sprintf("SharedKey %s:%s", k.accountName, signature))
	return nil
}

func header(key string, req *fasthttp.Request) string {
	// Use fasthttp's Peek method to get the header value.
	value := req.Header.Peek(key)
	if value == nil {
		return ""
	}
	return string(value)
}

func canonicalizedHeader(req *fasthttp.Request) string {
	cm := map[string][]string{}

	// Iterate over all headers in the request.
	req.Header.VisitAll(func(key, value []byte) {
		headerName := strings.TrimSpace(strings.ToLower(string(key)))
		if strings.HasPrefix(headerName, "x-ms-") {
			// Add the header to the map.
			cm[headerName] = append(cm[headerName], strings.TrimSpace(string(value)))
		}
	})

	if len(cm) == 0 {
		return ""
	}

	keys := make([]string, 0, len(cm))
	for key := range cm {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ch := bytes.NewBufferString("")
	for i, key := range keys {
		if i > 0 {
			ch.WriteRune('\n')
		}
		ch.WriteString(key)
		ch.WriteRune(':')
		ch.WriteString(strings.Join(cm[key], ","))
	}
	return ch.String()
}

func canonicalizedResource(accountName string, u *url.URL) (string, error) {
	// https://docs.microsoft.com/en-us/rest/api/storageservices/authentication-for-the-azure-storage-services
	cr := bytes.NewBufferString("/")
	cr.WriteString(accountName)

	if len(u.Path) > 0 {
		// Any portion of the CanonicalizedResource string that is derived from
		// the resource's URI should be encoded exactly as it is in the URI.
		// -- https://msdn.microsoft.com/en-gb/library/azure/dd179428.aspx
		cr.WriteString(u.EscapedPath())
	} else {
		// a slash is required to indicate the root path
		cr.WriteString("/")
	}

	// queryParams is a map[string][]string; param name is key; queryParams values is []string
	queryParams, err := url.ParseQuery(u.RawQuery) // Returns URL decoded values
	if err != nil {
		return "", fmt.Errorf("failed to parse query params: %w", err)
	}

	if len(queryParams) > 0 { // There is at least 1 query parameter
		var parameterNames []string // We use this to sort the parameter key names
		for parameterName := range queryParams {
			parameterNames = append(parameterNames, parameterName) // paramNames must be lowercase
		}
		sort.Strings(parameterNames)

		for _, pn := range parameterNames {
			paramValues := queryParams[pn]
			sort.Strings(paramValues)
			// Join the sorted key values separated by ','
			// Then prepend "keyName:"; then add this string to the buffer
			cr.WriteString("\n" + strings.ToLower(pn) + ":" + strings.Join(paramValues, ","))
		}
	}
	return cr.String(), nil
}
