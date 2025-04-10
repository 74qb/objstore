package azure

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/valyala/fasthttp"
)

type fastHTTPBlobClient struct {
	baseURL string
	client  *fasthttp.Client
	cred    *container.SharedKeyCredential
}

func NewFastHTTPBlobClient(blobURL string, cred *container.SharedKeyCredential) blobClient {
	return &fastHTTPBlobClient{
		baseURL: blobURL,
		client:  &fasthttp.Client{},
		cred:    cred,
	}
}

func (c *fastHTTPBlobClient) GetProperties(ctx context.Context, options *blob.GetPropertiesOptions) (blob.GetPropertiesResponse, error) {
	url := fmt.Sprintf("%s?comp=properties", c.baseURL)
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI(url)
	req.Header.SetMethod(fasthttp.MethodHead)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if err := c.client.Do(req, resp); err != nil {
		return blob.GetPropertiesResponse{}, fmt.Errorf("failed to get properties: %w", err)
	}

	if resp.StatusCode() != fasthttp.StatusOK {
		return blob.GetPropertiesResponse{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode())
	}

	// Parse response headers into blob.GetPropertiesResponse
	response := blob.GetPropertiesResponse{
		// Populate fields from response headers as needed
		ContentLength: to.Ptr(int64(resp.Header.ContentLength())),
		LastModified:  to.Ptr(time.Now()), // Replace with actual parsing from headers
	}

	return response, nil
}

func (c *fastHTTPBlobClient) Delete(ctx context.Context, options *blob.DeleteOptions) (blob.DeleteResponse, error) {
	url := fmt.Sprintf("%s", c.baseURL)
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI(url)
	req.Header.SetMethod(fasthttp.MethodDelete)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if err := c.client.Do(req, resp); err != nil {
		return blob.DeleteResponse{}, fmt.Errorf("failed to delete blob: %w", err)
	}

	if resp.StatusCode() != fasthttp.StatusAccepted {
		return blob.DeleteResponse{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode())
	}

	return blob.DeleteResponse{}, nil
}

func (c *fastHTTPBlobClient) DownloadStream(ctx context.Context, options *blob.DownloadStreamOptions) (blob.DownloadStreamResponse, error) {
	url := fmt.Sprintf("%s", c.baseURL)
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI(url)
	req.Header.SetMethod(fasthttp.MethodGet)

	if options != nil && options.Range.Count != 0 && options.Range.Offset != 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", options.Range.Offset, options.Range.Offset+options.Range.Count-1))
	}

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if err := c.client.Do(req, resp); err != nil {
		return blob.DownloadStreamResponse{}, fmt.Errorf("failed to download blob: %w", err)
	}

	if resp.StatusCode() != fasthttp.StatusOK && resp.StatusCode() != fasthttp.StatusPartialContent {
		return blob.DownloadStreamResponse{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode())
	}

	response := blob.DownloadStreamResponse{
		DownloadResponse: blob.DownloadResponse{
			AcceptRanges:       to.Ptr(string(resp.Header.Peek("Accept-Ranges"))),
			BlobContentMD5:     resp.Header.Peek("x-ms-blob-content-md5"),
			BlobSequenceNumber: to.Ptr(parseInt64(resp.Header.Peek("x-ms-blob-sequence-number"))),
			BlobType:           parseBlobType(resp.Header.Peek("x-ms-blob-type")),
			CacheControl:       to.Ptr(string(resp.Header.Peek("Cache-Control"))),
			ContentDisposition: to.Ptr(string(resp.Header.Peek("Content-Disposition"))),
			ContentEncoding:    to.Ptr(string(resp.Header.Peek("Content-Encoding"))),
			ContentLanguage:    to.Ptr(string(resp.Header.Peek("Content-Language"))),
			ContentLength:      to.Ptr(parseInt64(resp.Header.Peek("Content-Length"))),
			ContentMD5:         resp.Header.Peek("Content-MD5"),
			ContentRange:       to.Ptr(string(resp.Header.Peek("Content-Range"))),
			ContentType:        to.Ptr(string(resp.Header.Peek("Content-Type"))),
			CreationTime:       parseTime(resp.Header.Peek("x-ms-creation-time")),
			Date:               parseTime(resp.Header.Peek("Date")),
			ETag:               to.Ptr(azcore.ETag(string(resp.Header.Peek("ETag")))),
			LastModified:       parseTime(resp.Header.Peek("Last-Modified")),
			Metadata:           parseMetadata(resp),
			Body:               io.NopCloser(bytes.NewReader(resp.Body())),
		},
	}

	return response, nil
}

func parseInt64(value []byte) int64 {
	if value == nil {
		return 0
	}
	result, err := strconv.ParseInt(string(value), 10, 64)
	if err != nil {
		return 0
	}
	return result
}

func parseTime(value []byte) *time.Time {
	if value == nil {
		return nil
	}
	parsedTime, err := time.Parse(time.RFC1123, string(value))
	if err != nil {
		return nil
	}
	return &parsedTime
}

func parseBlobType(value []byte) *blob.BlobType {
	if value == nil {
		return nil
	}
	blobType := blob.BlobType(string(value))
	return &blobType
}

func parseMetadata(resp *fasthttp.Response) map[string]*string {
	metadata := make(map[string]*string)
	resp.Header.VisitAll(func(key, value []byte) {
		headerKey := string(key)
		if strings.HasPrefix(headerKey, "x-ms-meta-") {
			metadata[strings.TrimPrefix(headerKey, "x-ms-meta-")] = to.Ptr(string(value))
		}
	})
	return metadata
}

func (c *fastHTTPBlobClient) URL() string {
	return c.baseURL
}
