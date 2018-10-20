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
	"github.com/stretchr/testify/assert"
	"testing"
)

var allMsgTypes = [...]MsgType{
	Create,
	Delete,
	Set,
	Get,
	GetAllAlarms,
	GetAllAlarmsNext,
	MibUpload,
	MibUploadNext,
	MibReset,
	AlarmNotification,
	AttributeValueChange,
	Test,
	StartSoftwareDownload,
	DownloadSection,
	EndSoftwareDownload,
	ActivateSoftware,
	CommitSoftware,
	SynchronizeTime,
	Reboot,
	GetNext,
	TestResult,
	GetCurrentData,
	SetTable}

var allResults = [...]Results{
	Success,
	ProcessingError,
	NotSupported,
	ParameterError,
	UnknownEntity,
	UnknownInstance,
	DeviceBusy,
	InstanceExists}

var allNotificationTypes = [...]MsgType{
	AlarmNotification,
	AttributeValueChange,
	TestResult,
}

func isAutonomousNotification(mt MsgType) bool {
	for _, m := range allNotificationTypes {
		if mt == m {
			return true
		}
	}
	return false
}

// MibResetRequestTest tests decode/encode of a MIB Reset Request
func TestMsgTypeStrings(t *testing.T) {
	for _, msg := range allMsgTypes {
		strMsg := msg.String()
		assert.NotEqual(t, len(strMsg), 0)
	}
}

func TestResultsStrings(t *testing.T) {
	for _, code := range allResults {
		strMsg := code.String()
		assert.NotEqual(t, len(strMsg), 0)
	}
}

func TestAllDecoders(t *testing.T) {
	var requestMask byte = 0
	var responseMask byte = 0x20

	for _, msg := range allMsgTypes {
		// Test responses first since covers autonomous events
		mtResponse := byte(msg) | responseMask
		decoder, err := MsgTypeToStructDecoder(mtResponse)
		assert.Nil(t, err)
		assert.NotNil(t, decoder)

		// Autonomous notifications do not map to requests
		if isAutonomousNotification(msg) {
			continue
		}
		mtRequest := byte(msg) | requestMask
		decoder, err = MsgTypeToStructDecoder(mtRequest)
		assert.Nil(t, err)
		assert.NotNil(t, decoder)
	}
	// Unknown message type check
	var mt byte = 123
	decoder, err := MsgTypeToStructDecoder(mt)
	assert.NotNil(t, err)
	assert.Nil(t, decoder)

	// No autonomous notification requests
	for _, msg := range allNotificationTypes {
		mtRequest := byte(msg) | requestMask
		decoder, err = MsgTypeToStructDecoder(mtRequest)
		assert.NotNil(t, err)
		assert.Nil(t, decoder)
	}
}

func TestAllEncoders(t *testing.T) {
	var requestMask byte = 0
	var responseMask byte = 0x20

	for _, msg := range allMsgTypes {
		// Test responses first since covers autonomous events
		mtResponse := byte(msg) | responseMask
		encoder, err := MsgTypeToStructEncoder(mtResponse)
		assert.Nil(t, err)
		assert.NotNil(t, encoder)

		// Autonomous notifications do not map to requests
		if isAutonomousNotification(msg) {
			continue
		}
		mtRequest := byte(msg) | requestMask
		encoder, err = MsgTypeToStructEncoder(mtRequest)
		assert.Nil(t, err)
		assert.NotNil(t, encoder)
	}
	// Unknown message type check
	var mt byte = 123
	encoder, err := MsgTypeToStructEncoder(mt)
	assert.NotNil(t, err)
	assert.Nil(t, encoder)

	// No autonomous notification requests
	for _, msg := range allNotificationTypes {
		mtRequest := byte(msg) | requestMask
		encoder, err = MsgTypeToStructEncoder(mtRequest)
		assert.NotNil(t, err)
		assert.Nil(t, encoder)
	}
}
