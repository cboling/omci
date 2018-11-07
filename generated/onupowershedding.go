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
 *              https://github.com/cboling/OMCI-parser
 */
package generated

import (
	"../../omci"
)

type OnuPowerShedding struct {
	omci.BaseManagedEntity
}

func NewOnuPowerShedding(params ...ParamData) (IManagedEntity, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntity{
		name:     "OnuPowerShedding",
		classID:  133,
		entityID: eid,
		msgTypes: []omci.MsgType{
			omci.Set,
			omci.Get,
		},
		attributeList: []omci.IAttribute{
			omci.NewUint16Field("ManagedEntityId", 0, omci.Read),
			omci.NewUint16Field("RestorePowerTimerResetInterval", 0, omci.Read|omci.Write),
			omci.NewUint16Field("DataClassSheddingInterval", 0, omci.Read|omci.Write),
			omci.NewUint16Field("VoiceClassSheddingInterval", 0, omci.Read|omci.Write),
			omci.NewUint16Field("VideoOverlayClassSheddingInterval", 0, omci.Read|omci.Write),
			omci.NewUint16Field("VideoReturnClassSheddingInterval", 0, omci.Read|omci.Write),
			omci.NewUint16Field("DigitalSubscriberLineClassSheddingInterval", 0, omci.Read|omci.Write),
			omci.NewUint16Field("AtmClassSheddingInterval", 0, omci.Read|omci.Write),
			omci.NewUint16Field("CesClassSheddingInterval", 0, omci.Read|omci.Write),
			omci.NewUint16Field("FrameClassSheddingInterval", 0, omci.Read|omci.Write),
			omci.NewUint16Field("SdhSonetClassSheddingInterval", 0, omci.Read|omci.Write),
			omci.NewUint16Field("SheddingStatus", 0, omci.Read),
		},
	}
	entity.computeAttributeMask()
	return &OnuPowerShedding{entity}, nil
}
