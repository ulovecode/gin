// Copyright 2018 Gin Core Team.  All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package binding

type uriBinding struct{}

func (uriBinding) Name() string {
	return "uri"
}

// 把 map 解析到 obj 里
func (uriBinding) BindUri(m map[string][]string, obj interface{}) error {
	if err := mapUri(obj, m); err != nil {
		return err
	}
	return validate(obj)
}
