/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * NOTE: This file was generated, manual edits will be overwritten!
 *
 * Generated by 'goCodeGenerator.py':
 *              https://github.com/cboling/OMCI-parser/README.md
 */

package meframe

import (
	"errors"
	"fmt"
	. "github.com/cboling/omci"
	me "github.com/cboling/omci/generated"
	"github.com/google/gopacket"
)

func SetTableRequestFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat != ExtendedIdent {
		return nil, errors.New("set table message type only supported with Extended OMCI Messaging")
	}
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	mask, err := checkAttributeMask(m, opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &SetTableRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
	}
	// Get payload space available
	maxPayload := maxPacketAvailable(m, opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func SetTableResponseFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat != ExtendedIdent {
		return nil, errors.New("set table message type only supported with Extended OMCI Message Set")
	}
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	mask, err := checkAttributeMask(m, opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &SetTableResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       true,
		},
	}
	// Get payload space available
	maxPayload := maxPacketAvailable(m, opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}