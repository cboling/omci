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

type PhysicalPathTerminationPointPotsUni struct {
	omci.BaseManagedEntity
}

func NewPhysicalPathTerminationPointPotsUni(params ...ParamData) (IManagedEntity, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntity{
		name:     "PhysicalPathTerminationPointPotsUni",
		classID:  53,
		entityID: eid,
		msgTypes: []omci.MsgType{
			omci.Set,
			omci.Get,
			omci.Test,
		},
		attributeList: []omci.IAttribute{
			omci.NewUint16Field("ManagedEntityId", 0, omci.Read),
			omci.NewByteField("AdministrativeState", 0, omci.Read|omci.Write),
			omci.NewUint16Field("Deprecated", 0, omci.Read|omci.Write),
			omci.NewByteField("Arc", 0, omci.Read|omci.Write),
			omci.NewByteField("ArcInterval", 0, omci.Read|omci.Write),
			omci.NewByteField("Impedance", 0, omci.Read|omci.Write),
			omci.NewByteField("TransmissionPath", 0, omci.Read|omci.Write),
			omci.NewByteField("RxGain", 0, omci.Read|omci.Write),
			omci.NewByteField("TxGain", 0, omci.Read|omci.Write),
			omci.NewByteField("OperationalState", 0, omci.Read),
			omci.NewByteField("HookState", 0, omci.Read),
			omci.NewUint16Field("PotsHoldoverTime", 0, omci.Read|omci.Write),
			omci.NewByteField("NominalFeedVoltage", 0, omci.Read|omci.Write),
			omci.NewByteField("LossOfSoftswitch", 0, omci.Read|omci.Write),
		},
	}
	entity.computeAttributeMask()
	return &PhysicalPathTerminationPointPotsUni{entity}, nil
}
