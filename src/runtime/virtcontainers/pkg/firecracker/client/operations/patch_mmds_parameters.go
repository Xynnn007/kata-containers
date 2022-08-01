// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/firecracker/client/models"
)

// NewPatchMmdsParams creates a new PatchMmdsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPatchMmdsParams() *PatchMmdsParams {
	return &PatchMmdsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPatchMmdsParamsWithTimeout creates a new PatchMmdsParams object
// with the ability to set a timeout on a request.
func NewPatchMmdsParamsWithTimeout(timeout time.Duration) *PatchMmdsParams {
	return &PatchMmdsParams{
		timeout: timeout,
	}
}

// NewPatchMmdsParamsWithContext creates a new PatchMmdsParams object
// with the ability to set a context for a request.
func NewPatchMmdsParamsWithContext(ctx context.Context) *PatchMmdsParams {
	return &PatchMmdsParams{
		Context: ctx,
	}
}

// NewPatchMmdsParamsWithHTTPClient creates a new PatchMmdsParams object
// with the ability to set a custom HTTPClient for a request.
func NewPatchMmdsParamsWithHTTPClient(client *http.Client) *PatchMmdsParams {
	return &PatchMmdsParams{
		HTTPClient: client,
	}
}

/* PatchMmdsParams contains all the parameters to send to the API endpoint
   for the patch mmds operation.

   Typically these are written to a http.Request.
*/
type PatchMmdsParams struct {

	/* Body.

	   The MMDS data store patch JSON.
	*/
	Body models.MmdsContentsObject

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the patch mmds params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PatchMmdsParams) WithDefaults() *PatchMmdsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the patch mmds params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PatchMmdsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the patch mmds params
func (o *PatchMmdsParams) WithTimeout(timeout time.Duration) *PatchMmdsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the patch mmds params
func (o *PatchMmdsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the patch mmds params
func (o *PatchMmdsParams) WithContext(ctx context.Context) *PatchMmdsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the patch mmds params
func (o *PatchMmdsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the patch mmds params
func (o *PatchMmdsParams) WithHTTPClient(client *http.Client) *PatchMmdsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the patch mmds params
func (o *PatchMmdsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the patch mmds params
func (o *PatchMmdsParams) WithBody(body models.MmdsContentsObject) *PatchMmdsParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the patch mmds params
func (o *PatchMmdsParams) SetBody(body models.MmdsContentsObject) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PatchMmdsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
