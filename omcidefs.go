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
	me "./generated"
	"errors"
)

type IManagedEntityInstance interface {
	me.IManagedEntityDefinition

	GetAttributeMask() uint16
	SetAttributeMask(uint16) error

	GetAttributes() me.AttributeValueMap			// TODO: Can we use interface from generated?
	SetAttributes(me.AttributeValueMap) error
}

type BaseManagedEntityInstance struct {
	me.BaseManagedEntityDefinition
	AttributeMask uint16
	Attributes me.AttributeValueMap
}

func (bme *BaseManagedEntityInstance) GetAttributeMask() uint16 {
	return bme.AttributeMask
}
func (bme *BaseManagedEntityInstance) SetAttributeMask(mask uint16) error {
	if mask | bme.GetAllowedAttributeMask() != bme.GetAllowedAttributeMask() {
		return errors.New("invalid attribute mask")
	}
	bme.AttributeMask = mask
	return nil
}

func (bme *BaseManagedEntityInstance) GetAttributes() me.AttributeValueMap {
	return bme.Attributes
}
func (bme *BaseManagedEntityInstance) SetAttributes(attributes me.AttributeValueMap) error {
	// TODO: Validate attributes
	bme.Attributes = attributes
	return nil
}
