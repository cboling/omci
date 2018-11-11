/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package omci

import (
	"fmt"
)

///////////////////////////////////////////////////////////////////////
// Attribute Value   (Interfaced defined in generated subdirectory)

// AttributeValue provides the value for a single specific Managed Entity attribute
type AttributeValue struct {
	Name   string
	Index  uint
	Value  interface{}
}

func (attr *AttributeValue) String() string {
	val, err := attr.GetValue()
	return fmt.Sprintf("Value: %v, Index: %v, Value: %v, Error: %v",
		attr.GetName(), attr.GetIndex(), val, err)
}
func (attr *AttributeValue) GetName() string  { return attr.Name }
func (attr *AttributeValue) GetIndex() uint   { return attr.Index }
func (attr *AttributeValue) GetValue() (interface{}, error) {
	// TODO: Better way to detect not-initialized and no default available?
	return attr.Value, nil
}

func (attr *AttributeValue) SetValue(value interface{}) error {
	return nil
}