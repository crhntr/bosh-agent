// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"sync"

	"github.com/cloudfoundry/bosh-agent/platform/windows/disk"
)

type FakeWindowsDiskPartitioner struct {
	GetCountOnDiskStub        func(diskNumber string) (string, error)
	getCountOnDiskMutex       sync.RWMutex
	getCountOnDiskArgsForCall []struct {
		diskNumber string
	}
	getCountOnDiskReturns struct {
		result1 string
		result2 error
	}
	getCountOnDiskReturnsOnCall map[int]struct {
		result1 string
		result2 error
	}
	GetFreeSpaceOnDiskStub        func(diskNumber string) (int, error)
	getFreeSpaceOnDiskMutex       sync.RWMutex
	getFreeSpaceOnDiskArgsForCall []struct {
		diskNumber string
	}
	getFreeSpaceOnDiskReturns struct {
		result1 int
		result2 error
	}
	getFreeSpaceOnDiskReturnsOnCall map[int]struct {
		result1 int
		result2 error
	}
	InitializeDiskStub        func(diskNumber string) error
	initializeDiskMutex       sync.RWMutex
	initializeDiskArgsForCall []struct {
		diskNumber string
	}
	initializeDiskReturns struct {
		result1 error
	}
	initializeDiskReturnsOnCall map[int]struct {
		result1 error
	}
	PartitionDiskStub        func(diskNumber string) (string, error)
	partitionDiskMutex       sync.RWMutex
	partitionDiskArgsForCall []struct {
		diskNumber string
	}
	partitionDiskReturns struct {
		result1 string
		result2 error
	}
	partitionDiskReturnsOnCall map[int]struct {
		result1 string
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeWindowsDiskPartitioner) GetCountOnDisk(diskNumber string) (string, error) {
	fake.getCountOnDiskMutex.Lock()
	ret, specificReturn := fake.getCountOnDiskReturnsOnCall[len(fake.getCountOnDiskArgsForCall)]
	fake.getCountOnDiskArgsForCall = append(fake.getCountOnDiskArgsForCall, struct {
		diskNumber string
	}{diskNumber})
	fake.recordInvocation("GetCountOnDisk", []interface{}{diskNumber})
	fake.getCountOnDiskMutex.Unlock()
	if fake.GetCountOnDiskStub != nil {
		return fake.GetCountOnDiskStub(diskNumber)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.getCountOnDiskReturns.result1, fake.getCountOnDiskReturns.result2
}

func (fake *FakeWindowsDiskPartitioner) GetCountOnDiskCallCount() int {
	fake.getCountOnDiskMutex.RLock()
	defer fake.getCountOnDiskMutex.RUnlock()
	return len(fake.getCountOnDiskArgsForCall)
}

func (fake *FakeWindowsDiskPartitioner) GetCountOnDiskArgsForCall(i int) string {
	fake.getCountOnDiskMutex.RLock()
	defer fake.getCountOnDiskMutex.RUnlock()
	return fake.getCountOnDiskArgsForCall[i].diskNumber
}

func (fake *FakeWindowsDiskPartitioner) GetCountOnDiskReturns(result1 string, result2 error) {
	fake.GetCountOnDiskStub = nil
	fake.getCountOnDiskReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *FakeWindowsDiskPartitioner) GetCountOnDiskReturnsOnCall(i int, result1 string, result2 error) {
	fake.GetCountOnDiskStub = nil
	if fake.getCountOnDiskReturnsOnCall == nil {
		fake.getCountOnDiskReturnsOnCall = make(map[int]struct {
			result1 string
			result2 error
		})
	}
	fake.getCountOnDiskReturnsOnCall[i] = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *FakeWindowsDiskPartitioner) GetFreeSpaceOnDisk(diskNumber string) (int, error) {
	fake.getFreeSpaceOnDiskMutex.Lock()
	ret, specificReturn := fake.getFreeSpaceOnDiskReturnsOnCall[len(fake.getFreeSpaceOnDiskArgsForCall)]
	fake.getFreeSpaceOnDiskArgsForCall = append(fake.getFreeSpaceOnDiskArgsForCall, struct {
		diskNumber string
	}{diskNumber})
	fake.recordInvocation("GetFreeSpaceOnDisk", []interface{}{diskNumber})
	fake.getFreeSpaceOnDiskMutex.Unlock()
	if fake.GetFreeSpaceOnDiskStub != nil {
		return fake.GetFreeSpaceOnDiskStub(diskNumber)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.getFreeSpaceOnDiskReturns.result1, fake.getFreeSpaceOnDiskReturns.result2
}

func (fake *FakeWindowsDiskPartitioner) GetFreeSpaceOnDiskCallCount() int {
	fake.getFreeSpaceOnDiskMutex.RLock()
	defer fake.getFreeSpaceOnDiskMutex.RUnlock()
	return len(fake.getFreeSpaceOnDiskArgsForCall)
}

func (fake *FakeWindowsDiskPartitioner) GetFreeSpaceOnDiskArgsForCall(i int) string {
	fake.getFreeSpaceOnDiskMutex.RLock()
	defer fake.getFreeSpaceOnDiskMutex.RUnlock()
	return fake.getFreeSpaceOnDiskArgsForCall[i].diskNumber
}

func (fake *FakeWindowsDiskPartitioner) GetFreeSpaceOnDiskReturns(result1 int, result2 error) {
	fake.GetFreeSpaceOnDiskStub = nil
	fake.getFreeSpaceOnDiskReturns = struct {
		result1 int
		result2 error
	}{result1, result2}
}

func (fake *FakeWindowsDiskPartitioner) GetFreeSpaceOnDiskReturnsOnCall(i int, result1 int, result2 error) {
	fake.GetFreeSpaceOnDiskStub = nil
	if fake.getFreeSpaceOnDiskReturnsOnCall == nil {
		fake.getFreeSpaceOnDiskReturnsOnCall = make(map[int]struct {
			result1 int
			result2 error
		})
	}
	fake.getFreeSpaceOnDiskReturnsOnCall[i] = struct {
		result1 int
		result2 error
	}{result1, result2}
}

func (fake *FakeWindowsDiskPartitioner) InitializeDisk(diskNumber string) error {
	fake.initializeDiskMutex.Lock()
	ret, specificReturn := fake.initializeDiskReturnsOnCall[len(fake.initializeDiskArgsForCall)]
	fake.initializeDiskArgsForCall = append(fake.initializeDiskArgsForCall, struct {
		diskNumber string
	}{diskNumber})
	fake.recordInvocation("InitializeDisk", []interface{}{diskNumber})
	fake.initializeDiskMutex.Unlock()
	if fake.InitializeDiskStub != nil {
		return fake.InitializeDiskStub(diskNumber)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.initializeDiskReturns.result1
}

func (fake *FakeWindowsDiskPartitioner) InitializeDiskCallCount() int {
	fake.initializeDiskMutex.RLock()
	defer fake.initializeDiskMutex.RUnlock()
	return len(fake.initializeDiskArgsForCall)
}

func (fake *FakeWindowsDiskPartitioner) InitializeDiskArgsForCall(i int) string {
	fake.initializeDiskMutex.RLock()
	defer fake.initializeDiskMutex.RUnlock()
	return fake.initializeDiskArgsForCall[i].diskNumber
}

func (fake *FakeWindowsDiskPartitioner) InitializeDiskReturns(result1 error) {
	fake.InitializeDiskStub = nil
	fake.initializeDiskReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeWindowsDiskPartitioner) InitializeDiskReturnsOnCall(i int, result1 error) {
	fake.InitializeDiskStub = nil
	if fake.initializeDiskReturnsOnCall == nil {
		fake.initializeDiskReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.initializeDiskReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeWindowsDiskPartitioner) PartitionDisk(diskNumber string) (string, error) {
	fake.partitionDiskMutex.Lock()
	ret, specificReturn := fake.partitionDiskReturnsOnCall[len(fake.partitionDiskArgsForCall)]
	fake.partitionDiskArgsForCall = append(fake.partitionDiskArgsForCall, struct {
		diskNumber string
	}{diskNumber})
	fake.recordInvocation("PartitionDisk", []interface{}{diskNumber})
	fake.partitionDiskMutex.Unlock()
	if fake.PartitionDiskStub != nil {
		return fake.PartitionDiskStub(diskNumber)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.partitionDiskReturns.result1, fake.partitionDiskReturns.result2
}

func (fake *FakeWindowsDiskPartitioner) PartitionDiskCallCount() int {
	fake.partitionDiskMutex.RLock()
	defer fake.partitionDiskMutex.RUnlock()
	return len(fake.partitionDiskArgsForCall)
}

func (fake *FakeWindowsDiskPartitioner) PartitionDiskArgsForCall(i int) string {
	fake.partitionDiskMutex.RLock()
	defer fake.partitionDiskMutex.RUnlock()
	return fake.partitionDiskArgsForCall[i].diskNumber
}

func (fake *FakeWindowsDiskPartitioner) PartitionDiskReturns(result1 string, result2 error) {
	fake.PartitionDiskStub = nil
	fake.partitionDiskReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *FakeWindowsDiskPartitioner) PartitionDiskReturnsOnCall(i int, result1 string, result2 error) {
	fake.PartitionDiskStub = nil
	if fake.partitionDiskReturnsOnCall == nil {
		fake.partitionDiskReturnsOnCall = make(map[int]struct {
			result1 string
			result2 error
		})
	}
	fake.partitionDiskReturnsOnCall[i] = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *FakeWindowsDiskPartitioner) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.getCountOnDiskMutex.RLock()
	defer fake.getCountOnDiskMutex.RUnlock()
	fake.getFreeSpaceOnDiskMutex.RLock()
	defer fake.getFreeSpaceOnDiskMutex.RUnlock()
	fake.initializeDiskMutex.RLock()
	defer fake.initializeDiskMutex.RUnlock()
	fake.partitionDiskMutex.RLock()
	defer fake.partitionDiskMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeWindowsDiskPartitioner) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ disk.WindowsDiskPartitioner = new(FakeWindowsDiskPartitioner)
