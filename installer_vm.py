#!/bin/python
#
# Copyright (c) 2015 Nutanix Inc. All rights reserved.
#
# Author: jaspal.dhillon@nutanix.com
###########################################################
# Amended by: KalipayJ
# #####################
# /phoenix/imaging_helper/installer_vm.py
# Relaunch from /root/ with: ./ce_installer && screen -r
###########################################################
# This module installs a hypervisor in a VM
# backed by a SATADOM.
#
import glob
import math
import os
import re
import shlex
import signal
import sys
import time
from distutils.version import LooseVersion

sys.path.append(os.path.join(os.path.dirname(__file__), "../"))

import folder_central
import log
import sysUtil

from consts import ARCH_PPC
from layout import layout_tools
from shell import shell_cmd
from folder_utils import get_config_params

QEMU_DISK_RAW = folder_central.get_raw_disk_path()
QEMU_DISK_COW = folder_central.get_cow_disk_path()
RETRY_LIMIT = 2
HYP_INSTALL_TIMEOUT = dict(
    esx=15 * 2 * 60,
    hyperv=15 * 2 * 60,
    kvm=180 * 2 * 60,
    xen=10 * 2 * 60)
HYP_INSTALL_TIMEOUT_MAX = 180 * 60
QEMU_INSTALLATION_LOG_PATH = "/tmp/installer_vm.log"
# Minimum VMFS partition size for a ESXi HCI and a ESXi CO
# node is 20GB and 2GB respectively.
MIN_VMFS_PART_SIZE = 20 * 1024 * 1024 * 1024
MIN_VMFS_PART_SIZE_CO = 2 * 1024 * 1024 * 1024


def format_error_message(info, out, err, ret):
  """
  Format error messages nicely
  """
  message = ("Command terminated with non-zero exit code: %s\n"
             "Please check the stdout and stderr for more information.\n"
             "stdout:%s\nstderr:%s\n")
  message = message % (ret, out, err)
  return "%s\n%s" % (info, message)


class InstallerVM(object):
  """
  Functions:
  1. Get the details of node.
  2. Set up the InstallerVM.
  3. Install the hypervisor.
  """

  def __init__(self, hyp_type, param_list, hyp_version=None,
               iso=folder_central.get_installer_iso_path()):
    self.p_list = param_list
    self.dev = ""
    self.vm_id = None
    self.hyp_type = hyp_type
    self.hyp_version = hyp_version  # Only relevant for esx for now to
    # determine what machine type to use in qemu.
    self.iso_path = iso
    self.check_environment()

  def install_os(self, dev=None):
    """
    Instantiates a new InstallerVM.
    Will FATAL if one is already running.

    Args:
      dev: force install onto this raw device.

    Returns:
      True on success. Fatals otherwise.
    """

    # If an earlier instance of Phoenix failed, cleanup first
    if os.path.isfile("/tmp/fatal_marker"):
      try:
        # This is the last time cleanup in the workflow, so we remove the marker
        os.remove("/tmp/fatal_marker")
        # 15) SIGTERM
        command = ["pkill", "-15", "-f", "qemu-system-x86_64"]
        ret, out, err = shell_cmd(command, fatal=False)
        time.sleep(1)
      except:
        pass

    if self.vm_id:
      log.FATAL("A installer vm is already running on the phoenix.")

    # Give the installer VM at least 4GB and up to 32GB, scaled according to
    # the amount of host memory
    # _, meminfo = sysUtil.get_proc_info()
    # host_ram = sysUtil.parse_memory(meminfo)
    vm_ram = "64G"
    log.INFO("Installer VM memory = %s" % vm_ram)

    self.dev = dev or self._find_block_device()
    log.INFO("Installation Device = %s" % self.dev)

    # Installation device is SATADOM for non-ESXi.
    # For ESXi, it's a raw file.
    installation_device = self._get_installation_device()

    # ESXi will use the MAC address of QEMU's NIC as vmknic's MAC address,
    # The MAC addresses of all QEMU are same, to avoid conflicts, we pass the
    # real MAC address to QEMU.
    mac_address = self._get_mac_address()

    # ESXi has a ~5% chance to stuck at writing to disk in QEMU, retries
    # are helpful to recover.
    start_time = time.time()
    is_timedout = False
    command = self.get_installer_vm_config(
      vm_ram=vm_ram,
      installation_device=installation_device, mac_address=mac_address)
    log.INFO("Executing %s" % command)
    command = shlex.split(command, posix=False)
    ret, out, err = shell_cmd(command, fatal=False)
    if ret:
      message = "Could not launch the Installer VM"
      log.FATAL(format_error_message(message, out, err, ret))
    log.INFO("Installer VM is now running the installation")

    try:
      self.vm_id = int(open("installer_vm.pid").read())
    except (IOError, ValueError):
      message = "Could not get the pid of installer vm"
      log.FATAL(format_error_message(message, out, err, ret))
    log.INFO("Installer VM running with PID = %s" % self.vm_id)

    while self.is_installer_vm_running() and not is_timedout:
      time.sleep(30)
      # params_dict = get_config_params().get("hyp_timeout", {})
      timeout = 4800
      # params_dict.get(self.hyp_type) or HYP_INSTALL_TIMEOUT.get(
      #   self.hyp_type,
      #   HYP_INSTALL_TIMEOUT_MAX)
      time_passed = time.time() - start_time
      is_timedout = time_passed > timeout
      log.INFO("[%s/%s] Hypervisor installation in progress, checking again in 30 seconds, bruther"
           % (int(time_passed), timeout + 30))
    if is_timedout:
      log.INFO("InstallerVM timeout occurred")

      # Send QEMU installation logs to foundation
      if self.hyp_type == "kvm" and os.path.exists(QEMU_INSTALLATION_LOG_PATH):
        content = ""
        with open(QEMU_INSTALLATION_LOG_PATH, "r") as f:
          content = f.read()
        message = ("QEMU installation logs:\n%s" % content)
        log.monitoring_callback("file//installer_vm", message)
        log.INFO("Please take a look at installer_vm_*.log inside "
             "foundation logs to debug hypervisor installation issues")

      while self.is_installer_vm_running():
        log.INFO("Terminating InstallerVM(%s)" % self.vm_id)
        try:
          os.kill(self.vm_id, signal.SIGKILL)
          time.sleep(3)
        except OSError:
          log.INFO("InstallerVM(%s) Terminated" % self.vm_id)
          break
    else:
      log.INFO("Installer VM finished in %ss." % (time.time() - start_time))

    log.INFO("Hypervisor installation is done")

    self._rebase_and_commit_cow_disk()
    return True

  def is_installer_vm_running(self):
    "Check if installer VM is running"
    try:
      os.kill(self.vm_id, 0)
    except OSError:
      return False
    else:
      return True

  def _get_installation_device(self):
    """
    For ESXi, return a COW disk.
    For others, return SATADOM.
    """
    # To avoid further hacks in installer vm, we just pass the nvme
    # device as nvme to the installer vm, the dracut be able to take
    # care the partition and bootloaders. Maybe we should apply this
    # to AHV and other hypervisor as well.
    if self.hyp_type in ["linux"] and "nvme" in self.dev:
      return ("-drive file=%s,format=raw,if=none,id=nvme1"
              " -device nvme,drive=nvme1,serial=nvme-1" % self.dev)
    if self.hyp_type not in ["esx", "xen"]:
      cache = "writethrough"
      if self.hyp_type == "hyperv":
        cache = "unsafe"
      dev_arg = "-drive file=%s,cache=%s,format=raw" % (self.dev, cache)
      return dev_arg

    log.INFO("Creating raw disk at %s" % QEMU_DISK_RAW)
    out = sysUtil.get_disk_size_in_bytes(self.dev)
    if not out:
      log.FATAL("Failed to detect size of %s" % self.dev)

    satadom_size_byte = out.strip()
    log.INFO("blockdev --getsize64 returned %s" % satadom_size_byte)

    if (self.hyp_type == "esx"):
      if (LooseVersion(self.hyp_version) >= LooseVersion("7.0")):
        total_satadom_size_byte = int(satadom_size_byte)
        # Carve out 20 GB to create a VMFS parition for CVM's use.
        satadom_size_byte = total_satadom_size_byte - MIN_VMFS_PART_SIZE
        if self.p_list.compute_only:
          satadom_size_byte = total_satadom_size_byte - MIN_VMFS_PART_SIZE_CO
        # ENG-393349: Set max satadom size limit to 128 GB as we are expecting that
        # all the space will be taken by ESXi System Storage and no VMFS parition
        # will be created.
        satadom_size_byte = min(satadom_size_byte, (128 * 1024 * 1024 * 1024))
        vmfs_size_byte = total_satadom_size_byte - satadom_size_byte
        vmfs_size_gb = vmfs_size_byte / 1024**3
        satadom_size_byte = str(satadom_size_byte)
        log.INFO("Reserved %sGiB for a VMFS partition" % str(vmfs_size_gb))

      log.INFO("Advising ESXi that boot drive size is %s" % satadom_size_byte)

    command = ["truncate", "-s", satadom_size_byte, QEMU_DISK_RAW]
    ret, out, _ = shell_cmd(command, fatal=False)
    if ret:
      log.FATAL("Failed to create raw disk image")

    log.INFO("Creating cow disk at %s" % QEMU_DISK_COW)
    command = ["qemu-img", "create", "-o",
               "backing_file=%s,backing_fmt=raw" % QEMU_DISK_RAW,
               "-f", "qcow2", QEMU_DISK_COW]
    ret, out, _ = shell_cmd(command, fatal=False)
    if ret:
      log.FATAL("Failed to create cow disk image")
    return "-drive file=%s,format=qcow2" % QEMU_DISK_COW

  def _rebase_and_commit_cow_disk(self):
    """
    Commit the COW disk to SATADOM.
    """
    if self.hyp_type not in ["esx", "xen"]:
      return self.dev

    log.INFO("Rebasing cow disk at %s to %s" %
             (QEMU_DISK_COW, self.dev))
    command = ["qemu-img", "rebase", "-u", "-b", self.dev, QEMU_DISK_COW]
    ret, _, _ = shell_cmd(command, fatal=False)
    if ret:
      log.FATAL("Failed to rebase cow disk image")

    log.INFO("Commiting cow disk at %s" % QEMU_DISK_COW)
    command = ["qemu-img", "commit", "-p", QEMU_DISK_COW]
    commit_start = time.time()
    ret, _, _ = shell_cmd(command, timeout=40 * 60, fatal=False)
    commit_end = time.time()
    log.INFO("Commited in %0.1fs" % (commit_end - commit_start))
    if ret:
      log.FATAL("Failed to commit cow disk image.")

  def _check_for_kernel_parameters(self):
    """
    Phoenix must be booted up with these parameters.
    """
    required_parameters = [
      "intel_iommu=on",
      "kvm-intel.nested=1",
      "kvm-intel.ept=1",
      "kvm.ignore_msrs=1"
    ]
    command = [
      "cat",
      "/proc/cmdline"
    ]
    ret, out, err = shell_cmd(command, fatal=False)
    for parameter in required_parameters:
      if not parameter in out:
        message = "'%s' parameter missing from kernel arguments" % parameter
        log.FATAL(format_error_message(message, out, err, ret))

  def _check_qemu(self):
    """
    Check for qemu binary.
    """
    if not (os.path.exists(folder_central.get_qemu_path()) or
            os.path.exists(folder_central.get_qemu_path_ppc64le())):
      message = "Qemu binary is missing in Phoenix enviroment"
      log.FATAL(format_error_message(message, "", "", ""))

  def _find_block_device(self):
    """
    Find the installation device.
    """
    boot_device_info = layout_tools.get_boot_device_from_layout(\
                         self.p_list.hw_layout,
                         exclude_boot_serial=self.p_list.exclude_boot_serial)
    return boot_device_info.dev

  def _get_mac_address(self, iface="ANY"):
    """
    Returns the MAC address of interface iface.
    Args:
        iface(str): if "ANY" is passed it would search
                    all interface that starts with eth
                    and shall pick any one of those.
                    If passed any other string, it would
                    pick MAC address for that interface.
    """
    if iface == "ANY":
      file_list = glob.glob("/sys/class/net/eth*/address")
      if len(file_list) == 0:
        message = "Couldn't find NIC with valid MAC address"
        log.FATAL(format_error_message(message, "", "", ""))
      file_name = file_list[0]
    else:
      file_name = ("/sys/class/net/%s/address" % iface)
    command = [
        "cat", file_name
    ]
    ret, out, err = shell_cmd(command, fatal=False)
    if ret:
      message = "Could not read MAC address of %s" % iface
      log.FATAL(format_error_message(message, out, err, ret))

    return out.strip()

  def check_environment(self):
    """
    Some basic tests.
    """
    ret, arch, err = shell_cmd(["uname", "-m"])
    if arch == ARCH_PPC:
      shell_cmd(["ppc64_cpu", "--smt=off"])
      shell_cmd(["modprobe", "kvm-hv"])
    else:
      self._check_for_kernel_parameters()
    self._check_qemu()

  def get_installer_vm_config(self, vm_ram="16384",
                              qemu_machine_type="q35",
                              installation_device=None,
                              mac_address=None):
    """
    Returns the command line needed to launch the installer vm
    """
    installer_vm_template = folder_central.get_installer_vm_template()
    ret, arch, err = shell_cmd(["uname", "-m"])
    if arch == ARCH_PPC:
      installer_vm_template = folder_central.get_installer_vm_template_ppc64le()

    uefi_firmware = ""
    if sysUtil.check_if_system_booted_in_uefi():
      uefi_firmware_filepath = \
        "/usr/share/edk2.git/ovmf-x64/OVMF_CODE-pure-efi.fd"
      uefi_variables = "/usr/share/edk2.git/ovmf-x64/OVMF_VARS-pure-efi.fd"
      uefi_firmware = ("-drive file=%s,if=pflash,format=raw,unit=0,readonly=on "
                       "-drive file=%s,if=pflash,format=raw,unit=1"
                       % (uefi_firmware_filepath, uefi_variables))

    serial_file = ""
    if self.hyp_type == "kvm":
      serial_file = "-serial file:%s" % QEMU_INSTALLATION_LOG_PATH

    with open(installer_vm_template, "r") as fd:
      config_template = fd.read()

    cpu_model = "-smp 4"
    netdev = "user,id=net0,net=192.168.5.0/24"
    net_device = "e1000,netdev=net0,id=net0"
    extra_args = ''
    # Note: most installer only uses 1 cdrom, except for
    #  - "Linux", oemdrv.iso on the second CDROM for ks.cfg
    #  - AHV, AHV-metadata on the 2nd CDROM for metadata(ENG-385386)
    cdrom  = "-cdrom " + self.iso_path

    if self.hyp_type == "hyperv":
      # NOTE: WinPE for HyperV works well with Qemu's DHCP/nat network.
      # -netdev user,id=net0 -device e1000,netdev=net0,id=net0
      cpu_model = "-cpu host -smp 4"
    elif self.hyp_type == "esx":
      _, out, _ = shell_cmd(["lscpu"])
      if bool(re.search("AuthenticAMD", out, re.I)):
        cpu_model = "-cpu host -smp 4"
      else:
        cpu_model = "-cpu host,+vmx -smp 8"
      # Pick a high PCI slot number so that it is unlikely to be one that
      # is actually in use, potentially causing ESXi to enumerate a 10G NIC
      # ahead of a 1G NIC.  There would be no functional impact, but some
      # automated scripts might be confused by this event.
      net_device = "vmxnet3,netdev=net0,id=net0,addr=1d.0"
      if self.hyp_version and (
            LooseVersion(self.hyp_version) >= LooseVersion("6.0")):
        # DELL-702 ESXi 6.0 U3 6921384 A07 doesn't work with pc anymore.
        qemu_machine_type = "q35 -machine vmport=off"
      else:
        # pc_piix is required to install ESX 5.5.
        qemu_machine_type = "pc -machine vmport=off"
    elif self.hyp_type == "xen":
      cpu_model = "-cpu Haswell,+vmx,-x2apic -smp 4"
      qemu_machine_type = "q35"
    if self.hyp_type == "kvm":
      # check if metadata iso exists, add it to the second CDROM
      meta_iso = self.iso_path + "-meta.iso"
      if os.path.exists(meta_iso):
        log.DEBUG("Using AHV-metadata iso for AHV installation")
        cdrom = "-drive file=%s,media=cdrom" % self.iso_path
        extra_args += "-drive file=%s,media=cdrom" % meta_iso
    if self.hyp_type == "linux":
      cdrom = "-drive file=%s,media=cdrom" % self.iso_path
      oemiso = os.path.join(os.path.dirname(self.iso_path), "oemdrv.iso")
      extra_args += "-drive file=%s,media=cdrom" % oemiso
      # Sometimes Linux installer requires usb kbd/mouse to debug in vnc
      extra_args += " -usb -device usb-mouse -device usb-kbd"

    if not installation_device:
      installation_device = self.dev

    if mac_address:
      net_device += ",mac=%s" % mac_address

    kernel = initrd = commandline_args = None
    qemu_path = folder_central.get_qemu_path()
    if arch == ARCH_PPC:
      qemu_path = folder_central.get_qemu_path_ppc64le()
      kernel = folder_central.get_ppc_installer_kernel_path()
      initrd = folder_central.get_ppc_installer_initrd_path()
      commandline_args = "'cmdline ks=cdrom:/ks.cfg biosdevname=0 nomodeset'"

    config_template = config_template.format(
        qemu_path=qemu_path,
        uefi_firmware=uefi_firmware,
        serial_file=serial_file,
        vm_ram=vm_ram,
        qemu_machine_type=qemu_machine_type,
        kernel=kernel,
        initrd=initrd,
        commandline_args=commandline_args,
        installation_device=installation_device,
        cdrom=cdrom,
        netdev=netdev,
        net_device=net_device,
        cpu_model=cpu_model,
        extra_args=extra_args,
    )
    # Save it for debuggability purposes
    path = os.path.join(folder_central.get_imaging_helper_dir(),
                        "installer_vm.config")
    with open(path, "w") as fd:
      fd.write(config_template)
    return config_template.strip().replace("\\\n", "")
