# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
"""Miscelaneous information gathering plugins."""

__author__ = "Michael Cohen <scudette@google.com>"

import re

from rekall.plugins.darwin import common
from rekall.plugins.renderers import visual_aides

#
#
# class DarwinMapProcMemory(common.DarwinPlugin):
#     """Finds process-addressable memory and, thereby, narrows down kernel VM.
#
#     On 64-bit OS X, the entire physical address space is addressable in the
#     virtual address space of the kernel (same DTB as 'kernel_task'). Further,
#     portions of the kernel virtual memory are addressable using the DTBs of
#     each process, in order to enable the OS to handle interrupts without having
#     to flush the TLB. Additionally, a lot of memory conceptually belonging to
#     a process is actually backed by the UBC (unified buffer cache), which is
#     also mapped into the kernel virtual memory.
#
#     Taking into account the above, there are two basic ways of delineating
#     physical memory that unambigously backs the kernel:
#
#     Firstly, the cumulative approach is to start with nothing and selectively
#     add pages which are known, based on knowledge of the kernel's internals, to
#     contain data only exposed (addressable and accessible) to the kernel.
#
#     This approach can be implemented by using an address space layer that logs
#     page reads in combination with running all plugins/collectors.
#
#     Alternatively, the same can be done using heuristics - for example:
#     - Add pages known to back the zone allocator
#     - Add pages above the kernel base (0xffffff8000000000)
#
#     Secondly, a subtractive approach is to start with the entire
#     kernel-addressable VM and subtract process memory, which is identified by
#
#     On 64-bit OS X, it would appear that the entire physical address space is
#     mapped into the kernel virtual address space. With much of the
#     userland-addressable data being backed by the UBC (which is implemented in
#     the BSD layer), the distinction between kernel and process memory is
#     difficult to delineate: all physical memory is visible from the kernel VM
#     and large portions of the kernel VM are addressable (but not accessible)
#     from process
#     """
#     __name = "map_proc_memory"
#
#     PAGE_SIZE = 0x1000
#     DEFAULT_RESOLUTION = 0x1000
#     DEFAULT_QUERY = "Process/command is 'Finder'"
#
#     @classmethod
#     def args(cls, parser):
#         super(DarwinFindMemory, cls).args(parser)
#         parser.add_argument("--query", type="str",
#                             default=cls.DEFAULT_QUERY,
#                             help="Query string to match one or more processes.")
#         parser.add_argument("--resolution", type="int",
#                             default=cls.DEFAULT_RESOLUTION,
#                             help="Number of 0x1000 byte pages per chunk.")
#         parser.add_argument("--kernel_dump_path", type="str", default=None,
#                             help="(Optional) Path to dump only kernel memory.")
#
#     def __init__(self, query=None, resolution=None, kernel_dump_path=None):
#         self.query = query or self.DEFAULT_QUERY
#         self.resolution = resolution or self.DEFAULT_RESOLUTION
#         self.kernel_dump_path = kernel_dump_path
#
#         self.processes = self.session.entities.find(query)
#         self.vm = self.session.kernel_address_space
#         self.base = self.vm.base
#
#         # Get the size of the base AS, or die trying.
#         self.base_size = None
#         runs = getattr(self.base, "runs", None)
#         if runs:
#             self.base_size = runs[-1][0] + runs[-1][-1]
#         else:
#             fsize = getattr(self.base, "fsize", None)
#             if fsize:
#                 self.base_size = fsize
#
#         if not self.base_size:
#             raise AttributeError(
#                 "Don't know how to get size of physical AS %s." % self.base)
#
    

class DarwinShowProcessVM(common.DarwinPlugin):
    """TODO"""
    __name = "proc_phys_layout"

    PAGE_SIZE = 0x1000
    DEFAULT_RESOLUTION = 0x1000
    DEFAULT_QUERY = "Process/command is 'Finder'"

    @classmethod
    def args(cls, parser):
        super(DarwinShowProcessVM, cls).args(parser)
        parser.add_argument("--query", type="str",
                            default=cls.DEFAULT_QUERY,
                            help="Query string to match one or more processes.")
        parser.add_argument("--resolution", type="int",
                            default=cls.DEFAULT_RESOLUTION,
                            help="Number of 0x1000 byte pages per chunk.")

    def __init__(self, query=None, resolution=None, kernel_dump_path=None,
                 **kwargs):
        super(DarwinShowProcessVM, self).__init__(**kwargs)
        self.query = query or self.DEFAULT_QUERY
        self.resolution = resolution or self.DEFAULT_RESOLUTION

        self.processes = self.session.entities.find(query)
        self.vm = self.session.kernel_address_space
        self.base = self.vm.base

        # Get the size of the base AS, or die trying.
        self.base_size = self.base.end()

    def get_pages(self):
        pages = set()
        seen = set()
        
        for process in self.processes:
            proc = process["MemoryObject/base_object"]
            cmd = process["Process/command"]
            vm = proc.get_process_address_space()
            counter = 0
            for vaddr, paddr, size in vm.get_available_addresses():
                if counter % 1000 == 0:
                    self.session.report_progress(
                        ("%(spinner)s enumerating memory of %(cmd)s "
                         "(0x%(vaddr)x)"), vaddr=vaddr, cmd=cmd)
                counter += 1
                
                if not vm.vaddr_access(vaddr):
                    continue
                
                for page in xrange(size / self.PAGE_SIZE):
                    page_paddr = paddr + page * self.PAGE_SIZE
                    if page_paddr in seen:
                        continue
                    
                    seen.add(page)
                    
                    if page_paddr > self.base_size - self.PAGE_SIZE:
                        continue
                    
                    pages.add(page_paddr)

        return pages
    
    def render(self, renderer):
        chunk_size = self.PAGE_SIZE * self.resolution
        max_chunk = self.base_size / chunk_size + 1
        chunks = [0] * max_chunk
        
        renderer.table_header([
            dict(name="Physical pages backing process VM",
                 width=60, type="Heatmap", style="full")])

        counter = 0
        for page in self.get_pages():
            if counter % 1000 == 0:
                self.session.report_progress(
                    "%(spinner)s Merged %(n)d pages into heatmap.",
                    n=counter)
            counter += 1
            
            chunk = page / chunk_size
            chunks[chunk] += 1

        heatmap = visual_aides.Heatmap.from_memory_chunks(chunks=chunks,
                                                          caption="Offset (p)")
        renderer.table_row(heatmap)


class DarwinHeatmapKernel(common.DarwinPlugin):
    __name = "show_kernel_vm"


class DarwinDMSG(common.DarwinPlugin):
    """Print the kernel debug messages."""

    __name = "dmesg"

    def render(self, renderer):
        renderer.table_header([
            ("Message", "message", "<80")])

        # This is a circular buffer with the write pointer at the msg_bufx
        # member.
        msgbuf = self.profile.get_constant_object(
            "_msgbufp",
            target="Pointer",
            target_args=dict(
                target="msgbuf"
                )
            )

        # Make sure the buffer is not too large.
        size = min(msgbuf.msg_size, 0x400000)
        if 0 < msgbuf.msg_bufx < size:
            data = self.kernel_address_space.read(msgbuf.msg_bufc, size)
            data = data[msgbuf.msg_bufx: size] + data[0:msgbuf.msg_bufx]
            data = re.sub("\x00", "", data)

            for x in data.splitlines():
                renderer.table_row(x)


class DarwinMachineInfo(common.DarwinPlugin):
    """Show information about this machine."""

    __name = "machine_info"

    def render(self, renderer):
        renderer.table_header([("Attribute", "attribute", "20"),
                               ("Value", "value", "10")])

        info = self.profile.get_constant_object(
            "_machine_info", "machine_info")

        for member in info.members:
            renderer.table_row(member, info.m(member))


class DarwinMount(common.DarwinPlugin):
    """Show mount points."""

    __name = "mount"

    def render(self, renderer):
        renderer.table_header([
            ("Device", "device", "30"),
            ("Mount Point", "mount_point", "60"),
            ("Type", "type", "")])

        mount_list = self.profile.get_constant_object(
            "_mountlist", "mount")

        for mount in mount_list.walk_list("mnt_list.tqe_next", False):
            renderer.table_row(mount.mnt_vfsstat.f_mntonname,
                               mount.mnt_vfsstat.f_mntfromname,
                               mount.mnt_vfsstat.f_fstypename)

class DarwinPhysicalMap(common.DarwinPlugin):
    """Prints the EFI boot physical memory map."""

    __name = "phys_map"

    def render(self, renderer):
        renderer.table_header([
            ("Physical Start", "phys", "[addrpad]"),
            ("Physical End", "phys", "[addrpad]"),
            ("Virtual", "virt", "[addrpad]"),
            ("Pages", "pages", ">10"),
            ("Type", "type", "")])

        boot_params = self.profile.get_constant_object(
            "_PE_state", "PE_state").bootArgs

        # Code from:
        # xnu-1699.26.8/osfmk/i386/AT386/model_dep.c:560
        memory_map = self.profile.Array(
            boot_params.MemoryMap,
            vm=self.physical_address_space,
            target="EfiMemoryRange",
            target_size=int(boot_params.MemoryMapDescriptorSize),
            count=boot_params.MemoryMapSize/boot_params.MemoryMapDescriptorSize)

        ranges = []
        for memory_range in memory_map:
            start = memory_range.PhysicalStart
            end = (memory_range.PhysicalStart
                   + 0x1000
                   * memory_range.NumberOfPages)
            ranges.append((unicode(memory_range.Type), start, end))
            renderer.table_row(
                start,
                end,
                memory_range.VirtualStart.cast("Pointer"),
                memory_range.NumberOfPages,
                memory_range.Type)

        # Render a heatmap.

        # Automatically lower resolution for large images.
        resolution = 0x1000 * 0x10  # 16 pages - conservative start.
        column_count = 12
        end = ranges[-1][-1]
        # Keep it under 200 rows.
        while end / resolution / column_count > 200:
            resolution *= 2
        
        notes = ("Resolution: %(pages)d pages (%(mb).2f MB) per cell.\n"
                 "Note that colors of overlapping regions are blended "
                 "using a weighted average. Letters in cells indicate "
                 "which regions from the legend are present. They are "
                 "ordered proportionally, by their respective page "
                 "counts in each cell.") % dict(pages=resolution / 0x1000,
                                                  mb=resolution / 1024.0**2)
        
        legend = visual_aides.MapLegend(
            notes=notes,
            legend=[("Am", "kEfiACPIMemoryNVS", (0x00, 0xff, 0x00)),
                    ("Ar", "kEfiACPIReclaimMemory", (0xc7, 0xff, 0x50)),
                    ("Bc", "kEfiBootServicesCode", (0xff, 0xa5, 0x00)),
                    ("Bd", "kEfiBootServicesData", (0xff, 0x00, 0x00)),
                    ("M", "kEfiConventionalMemory", (0xff, 0xff, 0xff)),
                    ("Ec", "kEfiLoaderCode", (0x00, 0xff, 0xff)),
                    ("Ed", "kEfiLoaderData", (0x00, 0x00, 0xff)),
                    ("I", "kEfiMemoryMappedIO", (0xff, 0xff, 0x00)),
                    ("X", "kEfiReservedMemoryType", (0x00, 0x00, 0x00)),
                    ("Rc", "kEfiRuntimeServicesCode", (0xff, 0x00, 0xff)),
                    ("Rd", "kEfiRuntimeServicesData", (0xff, 0x00, 0x50))])

        heatmap = visual_aides.Heatmap.from_memory_ranges(
            caption="Offset (p)",
            legend=legend,
            ranges=ranges,
            resolution=resolution,
            column_count=column_count)

        renderer.table_header([
            dict(name="Visual mapping", width=120, style="full"),
            dict(name="Legend", orientation="vertical", style="full",
                 width=40)])
        
        renderer.table_row(heatmap, legend)


class DarwinBootParameters(common.DarwinPlugin):
    """Prints the kernel command line."""

    __name = "boot_cmdline"

    def render(self, renderer):
        boot_params = self.profile.get_constant_object(
            "_PE_state", "PE_state").bootArgs

        renderer.format("{0}", boot_params.CommandLine.cast("String"))
