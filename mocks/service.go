// Code generated by mockery v2.43.2. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	certs "github.com/absmach/certs"

	mock "github.com/stretchr/testify/mock"

	x509 "crypto/x509"
)

// Service is an autogenerated mock type for the Service type
type Service struct {
	mock.Mock
}

// GetEntityID provides a mock function with given fields: ctx, serialNumber
func (_m *Service) GetEntityID(ctx context.Context, serialNumber string) (string, error) {
	ret := _m.Called(ctx, serialNumber)

	if len(ret) == 0 {
		panic("no return value specified for GetEntityID")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (string, error)); ok {
		return rf(ctx, serialNumber)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) string); ok {
		r0 = rf(ctx, serialNumber)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, serialNumber)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IssueCert provides a mock function with given fields: ctx, entityID, entityType, ipAddrs
func (_m *Service) IssueCert(ctx context.Context, entityID string, entityType certs.EntityType, ipAddrs []string) (string, error) {
	ret := _m.Called(ctx, entityID, entityType, ipAddrs)

	if len(ret) == 0 {
		panic("no return value specified for IssueCert")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, certs.EntityType, []string) (string, error)); ok {
		return rf(ctx, entityID, entityType, ipAddrs)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, certs.EntityType, []string) string); ok {
		r0 = rf(ctx, entityID, entityType, ipAddrs)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, certs.EntityType, []string) error); ok {
		r1 = rf(ctx, entityID, entityType, ipAddrs)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListCerts provides a mock function with given fields: ctx, pm
func (_m *Service) ListCerts(ctx context.Context, pm certs.PageMetadata) (certs.CertificatePage, error) {
	ret := _m.Called(ctx, pm)

	if len(ret) == 0 {
		panic("no return value specified for ListCerts")
	}

	var r0 certs.CertificatePage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, certs.PageMetadata) (certs.CertificatePage, error)); ok {
		return rf(ctx, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, certs.PageMetadata) certs.CertificatePage); ok {
		r0 = rf(ctx, pm)
	} else {
		r0 = ret.Get(0).(certs.CertificatePage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, certs.PageMetadata) error); ok {
		r1 = rf(ctx, pm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// OCSP provides a mock function with given fields: ctx, serialNumber
func (_m *Service) OCSP(ctx context.Context, serialNumber string) (*certs.Certificate, int, *x509.Certificate, error) {
	ret := _m.Called(ctx, serialNumber)

	if len(ret) == 0 {
		panic("no return value specified for OCSP")
	}

	var r0 *certs.Certificate
	var r1 int
	var r2 *x509.Certificate
	var r3 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*certs.Certificate, int, *x509.Certificate, error)); ok {
		return rf(ctx, serialNumber)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *certs.Certificate); ok {
		r0 = rf(ctx, serialNumber)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*certs.Certificate)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) int); ok {
		r1 = rf(ctx, serialNumber)
	} else {
		r1 = ret.Get(1).(int)
	}

	if rf, ok := ret.Get(2).(func(context.Context, string) *x509.Certificate); ok {
		r2 = rf(ctx, serialNumber)
	} else {
		if ret.Get(2) != nil {
			r2 = ret.Get(2).(*x509.Certificate)
		}
	}

	if rf, ok := ret.Get(3).(func(context.Context, string) error); ok {
		r3 = rf(ctx, serialNumber)
	} else {
		r3 = ret.Error(3)
	}

	return r0, r1, r2, r3
}

// RenewCert provides a mock function with given fields: ctx, serialNumber
func (_m *Service) RenewCert(ctx context.Context, serialNumber string) error {
	ret := _m.Called(ctx, serialNumber)

	if len(ret) == 0 {
		panic("no return value specified for RenewCert")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, serialNumber)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RetrieveCert provides a mock function with given fields: ctx, token, serialNumber
func (_m *Service) RetrieveCert(ctx context.Context, token string, serialNumber string) (certs.Certificate, []byte, error) {
	ret := _m.Called(ctx, token, serialNumber)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveCert")
	}

	var r0 certs.Certificate
	var r1 []byte
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (certs.Certificate, []byte, error)); ok {
		return rf(ctx, token, serialNumber)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) certs.Certificate); ok {
		r0 = rf(ctx, token, serialNumber)
	} else {
		r0 = ret.Get(0).(certs.Certificate)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) []byte); ok {
		r1 = rf(ctx, token, serialNumber)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).([]byte)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, string) error); ok {
		r2 = rf(ctx, token, serialNumber)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// RetrieveCertDownloadToken provides a mock function with given fields: ctx, serialNumber
func (_m *Service) RetrieveCertDownloadToken(ctx context.Context, serialNumber string) (string, error) {
	ret := _m.Called(ctx, serialNumber)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveCertDownloadToken")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (string, error)); ok {
		return rf(ctx, serialNumber)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) string); ok {
		r0 = rf(ctx, serialNumber)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, serialNumber)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RevokeCert provides a mock function with given fields: ctx, serialNumber
func (_m *Service) RevokeCert(ctx context.Context, serialNumber string) error {
	ret := _m.Called(ctx, serialNumber)

	if len(ret) == 0 {
		panic("no return value specified for RevokeCert")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, serialNumber)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewService creates a new instance of Service. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewService(t interface {
	mock.TestingT
	Cleanup(func())
}) *Service {
	mock := &Service{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
