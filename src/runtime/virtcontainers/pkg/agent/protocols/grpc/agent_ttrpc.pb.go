// Code generated by protoc-gen-go-ttrpc. DO NOT EDIT.
// source: agent.proto
package grpc

import (
	context "context"
	ttrpc "github.com/containerd/ttrpc"
	protocols "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

type AgentServiceService interface {
	CreateContainer(context.Context, *CreateContainerRequest) (*emptypb.Empty, error)
	StartContainer(context.Context, *StartContainerRequest) (*emptypb.Empty, error)
	RemoveContainer(context.Context, *RemoveContainerRequest) (*emptypb.Empty, error)
	ExecProcess(context.Context, *ExecProcessRequest) (*emptypb.Empty, error)
	SignalProcess(context.Context, *SignalProcessRequest) (*emptypb.Empty, error)
	WaitProcess(context.Context, *WaitProcessRequest) (*WaitProcessResponse, error)
	UpdateContainer(context.Context, *UpdateContainerRequest) (*emptypb.Empty, error)
	UpdateEphemeralMounts(context.Context, *UpdateEphemeralMountsRequest) (*emptypb.Empty, error)
	StatsContainer(context.Context, *StatsContainerRequest) (*StatsContainerResponse, error)
	PauseContainer(context.Context, *PauseContainerRequest) (*emptypb.Empty, error)
	ResumeContainer(context.Context, *ResumeContainerRequest) (*emptypb.Empty, error)
	RemoveStaleVirtiofsShareMounts(context.Context, *RemoveStaleVirtiofsShareMountsRequest) (*emptypb.Empty, error)
	WriteStdin(context.Context, *WriteStreamRequest) (*WriteStreamResponse, error)
	ReadStdout(context.Context, *ReadStreamRequest) (*ReadStreamResponse, error)
	ReadStderr(context.Context, *ReadStreamRequest) (*ReadStreamResponse, error)
	CloseStdin(context.Context, *CloseStdinRequest) (*emptypb.Empty, error)
	TtyWinResize(context.Context, *TtyWinResizeRequest) (*emptypb.Empty, error)
	UpdateInterface(context.Context, *UpdateInterfaceRequest) (*protocols.Interface, error)
	UpdateRoutes(context.Context, *UpdateRoutesRequest) (*Routes, error)
	ListInterfaces(context.Context, *ListInterfacesRequest) (*Interfaces, error)
	ListRoutes(context.Context, *ListRoutesRequest) (*Routes, error)
	AddARPNeighbors(context.Context, *AddARPNeighborsRequest) (*emptypb.Empty, error)
	GetIPTables(context.Context, *GetIPTablesRequest) (*GetIPTablesResponse, error)
	SetIPTables(context.Context, *SetIPTablesRequest) (*SetIPTablesResponse, error)
	GetMetrics(context.Context, *GetMetricsRequest) (*Metrics, error)
	CreateSandbox(context.Context, *CreateSandboxRequest) (*emptypb.Empty, error)
	DestroySandbox(context.Context, *DestroySandboxRequest) (*emptypb.Empty, error)
	OnlineCPUMem(context.Context, *OnlineCPUMemRequest) (*emptypb.Empty, error)
	ReseedRandomDev(context.Context, *ReseedRandomDevRequest) (*emptypb.Empty, error)
	GetGuestDetails(context.Context, *GuestDetailsRequest) (*GuestDetailsResponse, error)
	MemHotplugByProbe(context.Context, *MemHotplugByProbeRequest) (*emptypb.Empty, error)
	SetGuestDateTime(context.Context, *SetGuestDateTimeRequest) (*emptypb.Empty, error)
	CopyFile(context.Context, *CopyFileRequest) (*emptypb.Empty, error)
	GetOOMEvent(context.Context, *GetOOMEventRequest) (*OOMEvent, error)
	AddSwap(context.Context, *AddSwapRequest) (*emptypb.Empty, error)
	GetVolumeStats(context.Context, *VolumeStatsRequest) (*VolumeStatsResponse, error)
	ResizeVolume(context.Context, *ResizeVolumeRequest) (*emptypb.Empty, error)
	SetPolicy(context.Context, *SetPolicyRequest) (*emptypb.Empty, error)
	SetInitdata(context.Context, *SetInitdataRequest) (*emptypb.Empty, error)
}

func RegisterAgentServiceService(srv *ttrpc.Server, svc AgentServiceService) {
	srv.RegisterService("grpc.AgentService", &ttrpc.ServiceDesc{
		Methods: map[string]ttrpc.Method{
			"CreateContainer": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req CreateContainerRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.CreateContainer(ctx, &req)
			},
			"StartContainer": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req StartContainerRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.StartContainer(ctx, &req)
			},
			"RemoveContainer": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req RemoveContainerRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.RemoveContainer(ctx, &req)
			},
			"ExecProcess": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req ExecProcessRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.ExecProcess(ctx, &req)
			},
			"SignalProcess": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req SignalProcessRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.SignalProcess(ctx, &req)
			},
			"WaitProcess": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req WaitProcessRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.WaitProcess(ctx, &req)
			},
			"UpdateContainer": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req UpdateContainerRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.UpdateContainer(ctx, &req)
			},
			"UpdateEphemeralMounts": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req UpdateEphemeralMountsRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.UpdateEphemeralMounts(ctx, &req)
			},
			"StatsContainer": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req StatsContainerRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.StatsContainer(ctx, &req)
			},
			"PauseContainer": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req PauseContainerRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.PauseContainer(ctx, &req)
			},
			"ResumeContainer": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req ResumeContainerRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.ResumeContainer(ctx, &req)
			},
			"RemoveStaleVirtiofsShareMounts": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req RemoveStaleVirtiofsShareMountsRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.RemoveStaleVirtiofsShareMounts(ctx, &req)
			},
			"WriteStdin": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req WriteStreamRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.WriteStdin(ctx, &req)
			},
			"ReadStdout": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req ReadStreamRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.ReadStdout(ctx, &req)
			},
			"ReadStderr": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req ReadStreamRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.ReadStderr(ctx, &req)
			},
			"CloseStdin": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req CloseStdinRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.CloseStdin(ctx, &req)
			},
			"TtyWinResize": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req TtyWinResizeRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.TtyWinResize(ctx, &req)
			},
			"UpdateInterface": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req UpdateInterfaceRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.UpdateInterface(ctx, &req)
			},
			"UpdateRoutes": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req UpdateRoutesRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.UpdateRoutes(ctx, &req)
			},
			"ListInterfaces": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req ListInterfacesRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.ListInterfaces(ctx, &req)
			},
			"ListRoutes": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req ListRoutesRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.ListRoutes(ctx, &req)
			},
			"AddARPNeighbors": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req AddARPNeighborsRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.AddARPNeighbors(ctx, &req)
			},
			"GetIPTables": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req GetIPTablesRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.GetIPTables(ctx, &req)
			},
			"SetIPTables": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req SetIPTablesRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.SetIPTables(ctx, &req)
			},
			"GetMetrics": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req GetMetricsRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.GetMetrics(ctx, &req)
			},
			"CreateSandbox": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req CreateSandboxRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.CreateSandbox(ctx, &req)
			},
			"DestroySandbox": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req DestroySandboxRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.DestroySandbox(ctx, &req)
			},
			"OnlineCPUMem": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req OnlineCPUMemRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.OnlineCPUMem(ctx, &req)
			},
			"ReseedRandomDev": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req ReseedRandomDevRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.ReseedRandomDev(ctx, &req)
			},
			"GetGuestDetails": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req GuestDetailsRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.GetGuestDetails(ctx, &req)
			},
			"MemHotplugByProbe": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req MemHotplugByProbeRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.MemHotplugByProbe(ctx, &req)
			},
			"SetGuestDateTime": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req SetGuestDateTimeRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.SetGuestDateTime(ctx, &req)
			},
			"CopyFile": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req CopyFileRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.CopyFile(ctx, &req)
			},
			"GetOOMEvent": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req GetOOMEventRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.GetOOMEvent(ctx, &req)
			},
			"AddSwap": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req AddSwapRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.AddSwap(ctx, &req)
			},
			"GetVolumeStats": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req VolumeStatsRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.GetVolumeStats(ctx, &req)
			},
			"ResizeVolume": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req ResizeVolumeRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.ResizeVolume(ctx, &req)
			},
			"SetPolicy": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req SetPolicyRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.SetPolicy(ctx, &req)
			},
			"SetInitdata": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req SetInitdataRequest
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.SetInitdata(ctx, &req)
			},
		},
	})
}

type agentserviceClient struct {
	client *ttrpc.Client
}

func NewAgentServiceClient(client *ttrpc.Client) AgentServiceService {
	return &agentserviceClient{
		client: client,
	}
}

func (c *agentserviceClient) CreateContainer(ctx context.Context, req *CreateContainerRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "CreateContainer", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) StartContainer(ctx context.Context, req *StartContainerRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "StartContainer", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) RemoveContainer(ctx context.Context, req *RemoveContainerRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "RemoveContainer", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) ExecProcess(ctx context.Context, req *ExecProcessRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "ExecProcess", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) SignalProcess(ctx context.Context, req *SignalProcessRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "SignalProcess", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) WaitProcess(ctx context.Context, req *WaitProcessRequest) (*WaitProcessResponse, error) {
	var resp WaitProcessResponse
	if err := c.client.Call(ctx, "grpc.AgentService", "WaitProcess", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) UpdateContainer(ctx context.Context, req *UpdateContainerRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "UpdateContainer", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) UpdateEphemeralMounts(ctx context.Context, req *UpdateEphemeralMountsRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "UpdateEphemeralMounts", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) StatsContainer(ctx context.Context, req *StatsContainerRequest) (*StatsContainerResponse, error) {
	var resp StatsContainerResponse
	if err := c.client.Call(ctx, "grpc.AgentService", "StatsContainer", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) PauseContainer(ctx context.Context, req *PauseContainerRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "PauseContainer", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) ResumeContainer(ctx context.Context, req *ResumeContainerRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "ResumeContainer", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) RemoveStaleVirtiofsShareMounts(ctx context.Context, req *RemoveStaleVirtiofsShareMountsRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "RemoveStaleVirtiofsShareMounts", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) WriteStdin(ctx context.Context, req *WriteStreamRequest) (*WriteStreamResponse, error) {
	var resp WriteStreamResponse
	if err := c.client.Call(ctx, "grpc.AgentService", "WriteStdin", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) ReadStdout(ctx context.Context, req *ReadStreamRequest) (*ReadStreamResponse, error) {
	var resp ReadStreamResponse
	if err := c.client.Call(ctx, "grpc.AgentService", "ReadStdout", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) ReadStderr(ctx context.Context, req *ReadStreamRequest) (*ReadStreamResponse, error) {
	var resp ReadStreamResponse
	if err := c.client.Call(ctx, "grpc.AgentService", "ReadStderr", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) CloseStdin(ctx context.Context, req *CloseStdinRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "CloseStdin", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) TtyWinResize(ctx context.Context, req *TtyWinResizeRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "TtyWinResize", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) UpdateInterface(ctx context.Context, req *UpdateInterfaceRequest) (*protocols.Interface, error) {
	var resp protocols.Interface
	if err := c.client.Call(ctx, "grpc.AgentService", "UpdateInterface", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) UpdateRoutes(ctx context.Context, req *UpdateRoutesRequest) (*Routes, error) {
	var resp Routes
	if err := c.client.Call(ctx, "grpc.AgentService", "UpdateRoutes", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) ListInterfaces(ctx context.Context, req *ListInterfacesRequest) (*Interfaces, error) {
	var resp Interfaces
	if err := c.client.Call(ctx, "grpc.AgentService", "ListInterfaces", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) ListRoutes(ctx context.Context, req *ListRoutesRequest) (*Routes, error) {
	var resp Routes
	if err := c.client.Call(ctx, "grpc.AgentService", "ListRoutes", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) AddARPNeighbors(ctx context.Context, req *AddARPNeighborsRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "AddARPNeighbors", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) GetIPTables(ctx context.Context, req *GetIPTablesRequest) (*GetIPTablesResponse, error) {
	var resp GetIPTablesResponse
	if err := c.client.Call(ctx, "grpc.AgentService", "GetIPTables", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) SetIPTables(ctx context.Context, req *SetIPTablesRequest) (*SetIPTablesResponse, error) {
	var resp SetIPTablesResponse
	if err := c.client.Call(ctx, "grpc.AgentService", "SetIPTables", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) GetMetrics(ctx context.Context, req *GetMetricsRequest) (*Metrics, error) {
	var resp Metrics
	if err := c.client.Call(ctx, "grpc.AgentService", "GetMetrics", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) CreateSandbox(ctx context.Context, req *CreateSandboxRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "CreateSandbox", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) DestroySandbox(ctx context.Context, req *DestroySandboxRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "DestroySandbox", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) OnlineCPUMem(ctx context.Context, req *OnlineCPUMemRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "OnlineCPUMem", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) ReseedRandomDev(ctx context.Context, req *ReseedRandomDevRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "ReseedRandomDev", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) GetGuestDetails(ctx context.Context, req *GuestDetailsRequest) (*GuestDetailsResponse, error) {
	var resp GuestDetailsResponse
	if err := c.client.Call(ctx, "grpc.AgentService", "GetGuestDetails", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) MemHotplugByProbe(ctx context.Context, req *MemHotplugByProbeRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "MemHotplugByProbe", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) SetGuestDateTime(ctx context.Context, req *SetGuestDateTimeRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "SetGuestDateTime", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) CopyFile(ctx context.Context, req *CopyFileRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "CopyFile", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) GetOOMEvent(ctx context.Context, req *GetOOMEventRequest) (*OOMEvent, error) {
	var resp OOMEvent
	if err := c.client.Call(ctx, "grpc.AgentService", "GetOOMEvent", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) AddSwap(ctx context.Context, req *AddSwapRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "AddSwap", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) GetVolumeStats(ctx context.Context, req *VolumeStatsRequest) (*VolumeStatsResponse, error) {
	var resp VolumeStatsResponse
	if err := c.client.Call(ctx, "grpc.AgentService", "GetVolumeStats", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) ResizeVolume(ctx context.Context, req *ResizeVolumeRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "ResizeVolume", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) SetPolicy(ctx context.Context, req *SetPolicyRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "SetPolicy", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentserviceClient) SetInitdata(ctx context.Context, req *SetInitdataRequest) (*emptypb.Empty, error) {
	var resp emptypb.Empty
	if err := c.client.Call(ctx, "grpc.AgentService", "SetInitdata", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
