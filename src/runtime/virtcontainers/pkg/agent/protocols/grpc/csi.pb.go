// Copyright (c) 2022 Databricks Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        v4.25.2
// source: csi.proto

package grpc

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type VolumeUsage_Unit int32

const (
	VolumeUsage_UNKNOWN VolumeUsage_Unit = 0
	VolumeUsage_BYTES   VolumeUsage_Unit = 1
	VolumeUsage_INODES  VolumeUsage_Unit = 2
)

// Enum value maps for VolumeUsage_Unit.
var (
	VolumeUsage_Unit_name = map[int32]string{
		0: "UNKNOWN",
		1: "BYTES",
		2: "INODES",
	}
	VolumeUsage_Unit_value = map[string]int32{
		"UNKNOWN": 0,
		"BYTES":   1,
		"INODES":  2,
	}
)

func (x VolumeUsage_Unit) Enum() *VolumeUsage_Unit {
	p := new(VolumeUsage_Unit)
	*p = x
	return p
}

func (x VolumeUsage_Unit) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (VolumeUsage_Unit) Descriptor() protoreflect.EnumDescriptor {
	return file_csi_proto_enumTypes[0].Descriptor()
}

func (VolumeUsage_Unit) Type() protoreflect.EnumType {
	return &file_csi_proto_enumTypes[0]
}

func (x VolumeUsage_Unit) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use VolumeUsage_Unit.Descriptor instead.
func (VolumeUsage_Unit) EnumDescriptor() ([]byte, []int) {
	return file_csi_proto_rawDescGZIP(), []int{1, 0}
}

// This should be kept in sync with CSI NodeGetVolumeStatsResponse (https://github.com/container-storage-interface/spec/blob/v1.5.0/csi.proto)
type VolumeStatsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// This field is OPTIONAL.
	Usage []*VolumeUsage `protobuf:"bytes,1,rep,name=usage,proto3" json:"usage,omitempty"`
	// Information about the current condition of the volume.
	// This field is OPTIONAL.
	// This field MUST be specified if the VOLUME_CONDITION node
	// capability is supported.
	VolumeCondition *VolumeCondition `protobuf:"bytes,2,opt,name=volume_condition,json=volumeCondition,proto3" json:"volume_condition,omitempty"`
}

func (x *VolumeStatsResponse) Reset() {
	*x = VolumeStatsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_csi_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VolumeStatsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VolumeStatsResponse) ProtoMessage() {}

func (x *VolumeStatsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_csi_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VolumeStatsResponse.ProtoReflect.Descriptor instead.
func (*VolumeStatsResponse) Descriptor() ([]byte, []int) {
	return file_csi_proto_rawDescGZIP(), []int{0}
}

func (x *VolumeStatsResponse) GetUsage() []*VolumeUsage {
	if x != nil {
		return x.Usage
	}
	return nil
}

func (x *VolumeStatsResponse) GetVolumeCondition() *VolumeCondition {
	if x != nil {
		return x.VolumeCondition
	}
	return nil
}

type VolumeUsage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The available capacity in specified Unit. This field is OPTIONAL.
	// The value of this field MUST NOT be negative.
	Available uint64 `protobuf:"varint,1,opt,name=available,proto3" json:"available,omitempty"`
	// The total capacity in specified Unit. This field is REQUIRED.
	// The value of this field MUST NOT be negative.
	Total uint64 `protobuf:"varint,2,opt,name=total,proto3" json:"total,omitempty"`
	// The used capacity in specified Unit. This field is OPTIONAL.
	// The value of this field MUST NOT be negative.
	Used uint64 `protobuf:"varint,3,opt,name=used,proto3" json:"used,omitempty"`
	// Units by which values are measured. This field is REQUIRED.
	Unit VolumeUsage_Unit `protobuf:"varint,4,opt,name=unit,proto3,enum=grpc.VolumeUsage_Unit" json:"unit,omitempty"`
}

func (x *VolumeUsage) Reset() {
	*x = VolumeUsage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_csi_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VolumeUsage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VolumeUsage) ProtoMessage() {}

func (x *VolumeUsage) ProtoReflect() protoreflect.Message {
	mi := &file_csi_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VolumeUsage.ProtoReflect.Descriptor instead.
func (*VolumeUsage) Descriptor() ([]byte, []int) {
	return file_csi_proto_rawDescGZIP(), []int{1}
}

func (x *VolumeUsage) GetAvailable() uint64 {
	if x != nil {
		return x.Available
	}
	return 0
}

func (x *VolumeUsage) GetTotal() uint64 {
	if x != nil {
		return x.Total
	}
	return 0
}

func (x *VolumeUsage) GetUsed() uint64 {
	if x != nil {
		return x.Used
	}
	return 0
}

func (x *VolumeUsage) GetUnit() VolumeUsage_Unit {
	if x != nil {
		return x.Unit
	}
	return VolumeUsage_UNKNOWN
}

// VolumeCondition represents the current condition of a volume.
type VolumeCondition struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Normal volumes are available for use and operating optimally.
	// An abnormal volume does not meet these criteria.
	// This field is REQUIRED.
	Abnormal bool `protobuf:"varint,1,opt,name=abnormal,proto3" json:"abnormal,omitempty"`
	// The message describing the condition of the volume.
	// This field is REQUIRED.
	Message string `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
}

func (x *VolumeCondition) Reset() {
	*x = VolumeCondition{}
	if protoimpl.UnsafeEnabled {
		mi := &file_csi_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VolumeCondition) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VolumeCondition) ProtoMessage() {}

func (x *VolumeCondition) ProtoReflect() protoreflect.Message {
	mi := &file_csi_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VolumeCondition.ProtoReflect.Descriptor instead.
func (*VolumeCondition) Descriptor() ([]byte, []int) {
	return file_csi_proto_rawDescGZIP(), []int{2}
}

func (x *VolumeCondition) GetAbnormal() bool {
	if x != nil {
		return x.Abnormal
	}
	return false
}

func (x *VolumeCondition) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

var File_csi_proto protoreflect.FileDescriptor

var file_csi_proto_rawDesc = []byte{
	0x0a, 0x09, 0x63, 0x73, 0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x04, 0x67, 0x72, 0x70,
	0x63, 0x22, 0x80, 0x01, 0x0a, 0x13, 0x56, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x53, 0x74, 0x61, 0x74,
	0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x27, 0x0a, 0x05, 0x75, 0x73, 0x61,
	0x67, 0x65, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x2e,
	0x56, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x55, 0x73, 0x61, 0x67, 0x65, 0x52, 0x05, 0x75, 0x73, 0x61,
	0x67, 0x65, 0x12, 0x40, 0x0a, 0x10, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x5f, 0x63, 0x6f, 0x6e,
	0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x67,
	0x72, 0x70, 0x63, 0x2e, 0x56, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x43, 0x6f, 0x6e, 0x64, 0x69, 0x74,
	0x69, 0x6f, 0x6e, 0x52, 0x0f, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x43, 0x6f, 0x6e, 0x64, 0x69,
	0x74, 0x69, 0x6f, 0x6e, 0x22, 0xad, 0x01, 0x0a, 0x0b, 0x56, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x55,
	0x73, 0x61, 0x67, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x09, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62,
	0x6c, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x05, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x12, 0x12, 0x0a, 0x04, 0x75, 0x73, 0x65, 0x64,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x52, 0x04, 0x75, 0x73, 0x65, 0x64, 0x12, 0x2a, 0x0a, 0x04,
	0x75, 0x6e, 0x69, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x16, 0x2e, 0x67, 0x72, 0x70,
	0x63, 0x2e, 0x56, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x55, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x55, 0x6e,
	0x69, 0x74, 0x52, 0x04, 0x75, 0x6e, 0x69, 0x74, 0x22, 0x2a, 0x0a, 0x04, 0x55, 0x6e, 0x69, 0x74,
	0x12, 0x0b, 0x0a, 0x07, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x09, 0x0a,
	0x05, 0x42, 0x59, 0x54, 0x45, 0x53, 0x10, 0x01, 0x12, 0x0a, 0x0a, 0x06, 0x49, 0x4e, 0x4f, 0x44,
	0x45, 0x53, 0x10, 0x02, 0x22, 0x47, 0x0a, 0x0f, 0x56, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x43, 0x6f,
	0x6e, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1a, 0x0a, 0x08, 0x61, 0x62, 0x6e, 0x6f, 0x72,
	0x6d, 0x61, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x61, 0x62, 0x6e, 0x6f, 0x72,
	0x6d, 0x61, 0x6c, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x60, 0x5a,
	0x5e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6b, 0x61, 0x74, 0x61,
	0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x73, 0x2f, 0x6b, 0x61, 0x74, 0x61,
	0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x73, 0x2f, 0x73, 0x72, 0x63, 0x2f,
	0x72, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x2f, 0x76, 0x69, 0x72, 0x74, 0x63, 0x6f, 0x6e, 0x74,
	0x61, 0x69, 0x6e, 0x65, 0x72, 0x73, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x61, 0x67, 0x65, 0x6e, 0x74,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x73, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_csi_proto_rawDescOnce sync.Once
	file_csi_proto_rawDescData = file_csi_proto_rawDesc
)

func file_csi_proto_rawDescGZIP() []byte {
	file_csi_proto_rawDescOnce.Do(func() {
		file_csi_proto_rawDescData = protoimpl.X.CompressGZIP(file_csi_proto_rawDescData)
	})
	return file_csi_proto_rawDescData
}

var file_csi_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_csi_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_csi_proto_goTypes = []interface{}{
	(VolumeUsage_Unit)(0),       // 0: grpc.VolumeUsage.Unit
	(*VolumeStatsResponse)(nil), // 1: grpc.VolumeStatsResponse
	(*VolumeUsage)(nil),         // 2: grpc.VolumeUsage
	(*VolumeCondition)(nil),     // 3: grpc.VolumeCondition
}
var file_csi_proto_depIdxs = []int32{
	2, // 0: grpc.VolumeStatsResponse.usage:type_name -> grpc.VolumeUsage
	3, // 1: grpc.VolumeStatsResponse.volume_condition:type_name -> grpc.VolumeCondition
	0, // 2: grpc.VolumeUsage.unit:type_name -> grpc.VolumeUsage.Unit
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_csi_proto_init() }
func file_csi_proto_init() {
	if File_csi_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_csi_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VolumeStatsResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_csi_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VolumeUsage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_csi_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VolumeCondition); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_csi_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_csi_proto_goTypes,
		DependencyIndexes: file_csi_proto_depIdxs,
		EnumInfos:         file_csi_proto_enumTypes,
		MessageInfos:      file_csi_proto_msgTypes,
	}.Build()
	File_csi_proto = out.File
	file_csi_proto_rawDesc = nil
	file_csi_proto_goTypes = nil
	file_csi_proto_depIdxs = nil
}
