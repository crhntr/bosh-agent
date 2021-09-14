package action_test

import (
	"github.com/cloudfoundry/bosh-agent/agent/utils/utilsfakes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"errors"

	. "github.com/cloudfoundry/bosh-agent/agent/action"
	"github.com/cloudfoundry/bosh-agent/platform/cert/certfakes"
	"github.com/cloudfoundry/bosh-agent/platform/platformfakes"
	"github.com/cloudfoundry/bosh-utils/logger"

	fakesettings "github.com/cloudfoundry/bosh-agent/settings/fakes"
	fakesys "github.com/cloudfoundry/bosh-utils/system/fakes"

	boshsettings "github.com/cloudfoundry/bosh-agent/settings"
)

var _ = Describe("UpdateSettings", func() {
	var (
		action            UpdateSettingsAction
		agentKiller       utilsfakes.FakeKiller
		certManager       *certfakes.FakeManager
		settingsService   *fakesettings.FakeSettingsService
		log               logger.Logger
		platform          *platformfakes.FakePlatform
		newUpdateSettings boshsettings.UpdateSettings
		fileSystem        *fakesys.FakeFileSystem
	)

	BeforeEach(func() {
		agentKiller = utilsfakes.FakeKiller{}
		log = logger.NewLogger(logger.LevelNone)
		certManager = new(certfakes.FakeManager)
		settingsService = &fakesettings.FakeSettingsService{}

		platform = &platformfakes.FakePlatform{}
		fileSystem = fakesys.NewFakeFileSystem()
		platform.GetFsReturns(fileSystem)

		action = NewUpdateSettings(settingsService, platform, certManager, log, &agentKiller)
		newUpdateSettings = boshsettings.UpdateSettings{}
	})

	AssertActionIsAsynchronous(action)
	AssertActionIsPersistent(action)
	AssertActionIsLoggable(action)

	AssertActionIsResumable(action)
	AssertActionIsNotCancelable(action)

	Context("on success", func() {
		It("returns 'ok'", func() {
			result, err := action.Run(newUpdateSettings)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("ok"))
		})

		It("writes the updated settings to a file", func() {
			action.Run(newUpdateSettings)
			Expect(settingsService.SaveUpdateSettingsCallCount).To(Equal(1))
		})
	})

	Context("when it fails to save the UpdateSettings", func() {
		BeforeEach(func() {
			settingsService.SaveUpdateSettingsErr = errors.New("Fake write error")
		})

		It("returns an error", func() {
			_, err := action.Run(newUpdateSettings)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Fake write error"))
		})
	})

	Context("when updating the certificates fails", func() {
		BeforeEach(func() {
			log = logger.NewLogger(logger.LevelNone)
			certManager = new(certfakes.FakeManager)
			certManager.UpdateCertificatesReturns(errors.New("Error"))
			action = NewUpdateSettings(settingsService, platform, certManager, log, &agentKiller)
		})

		It("returns the error", func() {
			result, err := action.Run(newUpdateSettings)
			Expect(err).To(HaveOccurred())
			Expect(result).To(BeEmpty())
		})
	})

	It("loads settings", func() {
		_, err := action.Run(newUpdateSettings)
		Expect(err).ToNot(HaveOccurred())
		Expect(settingsService.SettingsWereLoaded).To(BeTrue())
	})

	Context("when loading the settings fails", func() {
		It("returns an error", func() {
			settingsService.LoadSettingsError = errors.New("nope")
			_, err := action.Run(newUpdateSettings)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("when the settings does not contain the disk", func() {
		var (
			diskAssociation   boshsettings.DiskAssociation
			newUpdateSettings boshsettings.UpdateSettings
		)

		BeforeEach(func() {
			diskAssociation = boshsettings.DiskAssociation{
				Name:    "fake-disk-name",
				DiskCID: "fake-disk-id",
			}
			newUpdateSettings = boshsettings.UpdateSettings{
				DiskAssociations: []boshsettings.DiskAssociation{diskAssociation},
			}
			settingsService.GetPersistentDiskSettingsError = errors.New("Disk DNE")
		})

		It("returns the error", func() {
			_, err := action.Run(newUpdateSettings)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Fetching disk settings: Disk DNE"))
		})
	})

	It("associates the disks", func() {
		settingsService.PersistentDiskSettings = map[string]boshsettings.DiskSettings{
			"fake-disk-id": {
				VolumeID:     "fake-disk-volume-id",
				ID:           "fake-disk-id",
				DeviceID:     "fake-disk-device-id",
				Path:         "fake-disk-path",
				Lun:          "fake-disk-lun",
				HostDeviceID: "fake-disk-host-device-id",
			},
			"fake-disk-id-2": {
				VolumeID:     "fake-disk-volume-id-2",
				ID:           "fake-disk-id-2",
				DeviceID:     "fake-disk-device-id-2",
				Path:         "fake-disk-path-2",
				Lun:          "fake-disk-lun-2",
				HostDeviceID: "fake-disk-host-device-id-2",
			},
		}

		diskAssociation := boshsettings.DiskAssociation{
			Name:    "fake-disk-name",
			DiskCID: "fake-disk-id",
		}

		diskAssociation2 := boshsettings.DiskAssociation{
			Name:    "fake-disk-name2",
			DiskCID: "fake-disk-id-2",
		}

		_, err := action.Run(boshsettings.UpdateSettings{
			DiskAssociations: []boshsettings.DiskAssociation{
				diskAssociation,
				diskAssociation2,
			},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(platform.AssociateDiskCallCount()).To(Equal(2))

		actualDiskName, actualDiskSettings := platform.AssociateDiskArgsForCall(0)
		Expect(actualDiskName).To(Equal(diskAssociation.Name))
		Expect(actualDiskSettings).To(Equal(boshsettings.DiskSettings{
			ID:           "fake-disk-id",
			DeviceID:     "fake-disk-device-id",
			VolumeID:     "fake-disk-volume-id",
			Lun:          "fake-disk-lun",
			HostDeviceID: "fake-disk-host-device-id",
			Path:         "fake-disk-path",
		}))

		actualDiskName, actualDiskSettings = platform.AssociateDiskArgsForCall(1)
		Expect(actualDiskName).To(Equal(diskAssociation2.Name))
		Expect(actualDiskSettings).To(Equal(boshsettings.DiskSettings{
			ID:           "fake-disk-id-2",
			DeviceID:     "fake-disk-device-id-2",
			VolumeID:     "fake-disk-volume-id-2",
			Lun:          "fake-disk-lun-2",
			HostDeviceID: "fake-disk-host-device-id-2",
			Path:         "fake-disk-path-2",
		}))

		updateSettings := settingsService.SaveUpdateSettingsLastArg
		Expect(updateSettings.DiskAssociations[0].Name).To(Equal("fake-disk-name"))
	})

	Context("when updating nats or blobstore settings", func() {
		BeforeEach(func() {
			newUpdateSettings.Mbus.Cert.CA = "new ca cert"
			newUpdateSettings.Blobstores = append(newUpdateSettings.Blobstores, boshsettings.Blobstore{Type: "new blobstore"})
		})

		It("kills the agent", func() {
			Expect(func() {
				action.Run(newUpdateSettings)
			}).To(Panic())
			Expect(agentKiller.KillAgentCallCount()).To(Equal(1))
		})

		It("persists the new settings", func() {
			Expect(func() {
				action.Run(newUpdateSettings)
			}).To(Panic())

			updateSettings := settingsService.SaveUpdateSettingsLastArg
			Expect(updateSettings.Mbus.Cert.CA).To(Equal("new ca cert"))
			Expect(updateSettings.Blobstores[0].Type).To(Equal("new blobstore"))
		})
	})
})
