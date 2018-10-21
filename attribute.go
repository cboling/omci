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

// Attribute represents a single specific Managed Entity attribute
type IAttribute interface {
	// Name is the attribute name
	Name() string
	Access() AttributeAccess // TODO: For now, just make these strings....
	Size() int
	Value() (interface{}, error)
}

// Attribute represents a single specific Managed Entity attribute
type Attribute struct {
	name   string
	access AttributeAccess // TODO: For now, just make these strings....
	size   int
	value  interface{}
}

func (attr *Attribute) Name() string {
	return attr.name
}
func (attr *Attribute) Access() AttributeAccess {
	return attr.access
}
func (attr *Attribute) Size() int {
	return attr.size
}
func (attr *Attribute) Value() (interface{}, error) {
	// TODO: Better way to detect not-initialized and no default available?
	return attr.value, nil
}

//func decodeAttributes(classID uint16, mask uint16, data []byte, df gopacket.DecodeFeedback) ([]Attribute, error) {
//	managedEntity, err := LoadManagedEntityDefinition(classID)
//	if err != nil {
//		return nil, err
//	}
//	bitMask := bits.Len16(mask)
//	var attributes []Attribute
//
//	fmt.Println(managedEntity, bitMask)
//	//for index, bit := range bitMask {
//	//
//	//}
//	//	func ManagedEntityDecode(classID uint16, mask uint16, data []byte,
//	// 							 df gopacket.DecodeFeedback) (IManagedEntity, error) {
//
//	return attributes, errors.New("TODO: Need to perform decode")
//}
