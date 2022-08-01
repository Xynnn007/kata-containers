// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// FullVMConfiguration full Vm configuration
//
// swagger:model FullVmConfiguration
type FullVMConfiguration struct {

	// balloon
	Balloon *Balloon `json:"balloon,omitempty"`

	// boot source
	BootSource *BootSource `json:"boot-source,omitempty"`

	// Configurations for all block devices.
	Drives []*Drive `json:"drives"`

	// logger
	Logger *Logger `json:"logger,omitempty"`

	// machine config
	MachineConfig *MachineConfiguration `json:"machine-config,omitempty"`

	// metrics
	Metrics *Metrics `json:"metrics,omitempty"`

	// mmds config
	MmdsConfig *MmdsConfig `json:"mmds-config,omitempty"`

	// Configurations for all net devices.
	NetworkInterfaces []*NetworkInterface `json:"network-interfaces"`

	// vsock
	Vsock *Vsock `json:"vsock,omitempty"`
}

// Validate validates this full Vm configuration
func (m *FullVMConfiguration) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBalloon(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateBootSource(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDrives(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLogger(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMachineConfig(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMetrics(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMmdsConfig(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNetworkInterfaces(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVsock(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *FullVMConfiguration) validateBalloon(formats strfmt.Registry) error {
	if swag.IsZero(m.Balloon) { // not required
		return nil
	}

	if m.Balloon != nil {
		if err := m.Balloon.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("balloon")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("balloon")
			}
			return err
		}
	}

	return nil
}

func (m *FullVMConfiguration) validateBootSource(formats strfmt.Registry) error {
	if swag.IsZero(m.BootSource) { // not required
		return nil
	}

	if m.BootSource != nil {
		if err := m.BootSource.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("boot-source")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("boot-source")
			}
			return err
		}
	}

	return nil
}

func (m *FullVMConfiguration) validateDrives(formats strfmt.Registry) error {
	if swag.IsZero(m.Drives) { // not required
		return nil
	}

	for i := 0; i < len(m.Drives); i++ {
		if swag.IsZero(m.Drives[i]) { // not required
			continue
		}

		if m.Drives[i] != nil {
			if err := m.Drives[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("drives" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("drives" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *FullVMConfiguration) validateLogger(formats strfmt.Registry) error {
	if swag.IsZero(m.Logger) { // not required
		return nil
	}

	if m.Logger != nil {
		if err := m.Logger.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("logger")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("logger")
			}
			return err
		}
	}

	return nil
}

func (m *FullVMConfiguration) validateMachineConfig(formats strfmt.Registry) error {
	if swag.IsZero(m.MachineConfig) { // not required
		return nil
	}

	if m.MachineConfig != nil {
		if err := m.MachineConfig.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("machine-config")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("machine-config")
			}
			return err
		}
	}

	return nil
}

func (m *FullVMConfiguration) validateMetrics(formats strfmt.Registry) error {
	if swag.IsZero(m.Metrics) { // not required
		return nil
	}

	if m.Metrics != nil {
		if err := m.Metrics.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("metrics")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("metrics")
			}
			return err
		}
	}

	return nil
}

func (m *FullVMConfiguration) validateMmdsConfig(formats strfmt.Registry) error {
	if swag.IsZero(m.MmdsConfig) { // not required
		return nil
	}

	if m.MmdsConfig != nil {
		if err := m.MmdsConfig.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("mmds-config")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("mmds-config")
			}
			return err
		}
	}

	return nil
}

func (m *FullVMConfiguration) validateNetworkInterfaces(formats strfmt.Registry) error {
	if swag.IsZero(m.NetworkInterfaces) { // not required
		return nil
	}

	for i := 0; i < len(m.NetworkInterfaces); i++ {
		if swag.IsZero(m.NetworkInterfaces[i]) { // not required
			continue
		}

		if m.NetworkInterfaces[i] != nil {
			if err := m.NetworkInterfaces[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("network-interfaces" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("network-interfaces" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *FullVMConfiguration) validateVsock(formats strfmt.Registry) error {
	if swag.IsZero(m.Vsock) { // not required
		return nil
	}

	if m.Vsock != nil {
		if err := m.Vsock.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("vsock")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("vsock")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this full Vm configuration based on the context it is used
func (m *FullVMConfiguration) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateBalloon(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateBootSource(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDrives(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateLogger(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMachineConfig(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMetrics(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMmdsConfig(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateNetworkInterfaces(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateVsock(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *FullVMConfiguration) contextValidateBalloon(ctx context.Context, formats strfmt.Registry) error {

	if m.Balloon != nil {
		if err := m.Balloon.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("balloon")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("balloon")
			}
			return err
		}
	}

	return nil
}

func (m *FullVMConfiguration) contextValidateBootSource(ctx context.Context, formats strfmt.Registry) error {

	if m.BootSource != nil {
		if err := m.BootSource.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("boot-source")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("boot-source")
			}
			return err
		}
	}

	return nil
}

func (m *FullVMConfiguration) contextValidateDrives(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Drives); i++ {

		if m.Drives[i] != nil {
			if err := m.Drives[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("drives" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("drives" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *FullVMConfiguration) contextValidateLogger(ctx context.Context, formats strfmt.Registry) error {

	if m.Logger != nil {
		if err := m.Logger.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("logger")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("logger")
			}
			return err
		}
	}

	return nil
}

func (m *FullVMConfiguration) contextValidateMachineConfig(ctx context.Context, formats strfmt.Registry) error {

	if m.MachineConfig != nil {
		if err := m.MachineConfig.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("machine-config")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("machine-config")
			}
			return err
		}
	}

	return nil
}

func (m *FullVMConfiguration) contextValidateMetrics(ctx context.Context, formats strfmt.Registry) error {

	if m.Metrics != nil {
		if err := m.Metrics.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("metrics")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("metrics")
			}
			return err
		}
	}

	return nil
}

func (m *FullVMConfiguration) contextValidateMmdsConfig(ctx context.Context, formats strfmt.Registry) error {

	if m.MmdsConfig != nil {
		if err := m.MmdsConfig.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("mmds-config")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("mmds-config")
			}
			return err
		}
	}

	return nil
}

func (m *FullVMConfiguration) contextValidateNetworkInterfaces(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.NetworkInterfaces); i++ {

		if m.NetworkInterfaces[i] != nil {
			if err := m.NetworkInterfaces[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("network-interfaces" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("network-interfaces" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *FullVMConfiguration) contextValidateVsock(ctx context.Context, formats strfmt.Registry) error {

	if m.Vsock != nil {
		if err := m.Vsock.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("vsock")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("vsock")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *FullVMConfiguration) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FullVMConfiguration) UnmarshalBinary(b []byte) error {
	var res FullVMConfiguration
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
