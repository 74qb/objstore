// Copyright (c) The Thanos Authors.
// Licensed under the Apache License 2.0.

// Copyright (C) 2024 Bosch Security Systems  (BT-VS/ESW-REA) jakub.klimasz@de.bosch.com

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//         http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Modification history:
// * 15.07.2024 Added Upload with attributes.

package objstore

import (
	"context"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/efficientgo/core/testutil"
)

func TestPrefixedBucket_Acceptance(t *testing.T) {

	prefixes := []string{
		"/someprefix/anotherprefix/",
		"someprefix/anotherprefix/",
		"someprefix/anotherprefix",
		"someprefix/",
		"someprefix"}

	for _, prefix := range prefixes {
		AcceptanceTest(t, NewPrefixedBucket(NewInMemBucket(), prefix))
		UsesPrefixTest(t, NewInMemBucket(), prefix)
	}
}

func UsesPrefixTest(t *testing.T, bkt Bucket, prefix string) {
	testutil.Ok(t, bkt.Upload(context.Background(), strings.Trim(prefix, "/")+"/file1.jpg", strings.NewReader("test-data1")))

	pBkt := NewPrefixedBucket(bkt, prefix)
	rc1, err := pBkt.Get(context.Background(), "file1.jpg")
	testutil.Ok(t, err)

	testutil.Ok(t, err)
	defer func() { testutil.Ok(t, rc1.Close()) }()
	content, err := io.ReadAll(rc1)
	testutil.Ok(t, err)
	testutil.Equals(t, "test-data1", string(content))

	testutil.Ok(t, pBkt.Upload(context.Background(), "file2.jpg", strings.NewReader("test-data2")))
	rc2, err := bkt.Get(context.Background(), strings.Trim(prefix, "/")+"/file2.jpg")
	testutil.Ok(t, err)
	defer func() { testutil.Ok(t, rc2.Close()) }()
	contentUpload, err := io.ReadAll(rc2)
	testutil.Ok(t, err)
	testutil.Equals(t, "test-data2", string(contentUpload))

	testutil.Ok(t, pBkt.Delete(context.Background(), "file2.jpg"))
	_, err = bkt.Get(context.Background(), strings.Trim(prefix, "/")+"/file2.jpg")
	testutil.NotOk(t, err)
	testutil.Assert(t, pBkt.IsObjNotFoundErr(err), "expected not found error got %s", err)

	rc3, err := pBkt.GetRange(context.Background(), "file1.jpg", 1, 3)
	testutil.Ok(t, err)
	defer func() { testutil.Ok(t, rc3.Close()) }()
	content, err = io.ReadAll(rc3)
	testutil.Ok(t, err)
	testutil.Equals(t, "est", string(content))

	ok, err := pBkt.Exists(context.Background(), "file1.jpg")
	testutil.Ok(t, err)
	testutil.Assert(t, ok, "expected exits")

	attrs, err := pBkt.Attributes(context.Background(), "file1.jpg")
	testutil.Ok(t, err)
	testutil.Assert(t, attrs.Size == 10, "expected size to be equal to 10")

	testutil.Ok(t, bkt.Upload(context.Background(), strings.Trim(prefix, "/")+"/dir/file1.jpg", strings.NewReader("test-data1")))
	seen := []string{}
	testutil.Ok(t, pBkt.Iter(context.Background(), "", func(fn string) error {
		seen = append(seen, fn)
		return nil
	}, WithRecursiveIter()))
	expected := []string{"dir/file1.jpg", "file1.jpg"}
	sort.Strings(expected)
	sort.Strings(seen)
	testutil.Equals(t, expected, seen)

	seen = []string{}
	testutil.Ok(t, pBkt.Iter(context.Background(), "", func(fn string) error {
		seen = append(seen, fn)
		return nil
	}))
	expected = []string{"dir/", "file1.jpg"}
	sort.Strings(expected)
	sort.Strings(seen)
	testutil.Equals(t, expected, seen)
}
