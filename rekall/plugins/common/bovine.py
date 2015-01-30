# Rekall Memory Forensics
# Copyright 2014 Google Inc. All Rights Reserved.
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
#

"""The plugins in this module are mainly used to visually test renderers."""

__author__ = "Adam Sindelar <adamsh@google.com>"

import itertools

from rekall import plugin
from rekall import utils

from rekall.plugins.renderers import visual_aides

from rekall.ui import colors


class RekallBovineExperience3000(plugin.Command):
    """Renders Bessy the cow and some beer.
    
    This is a text renderer stress-test. It uses multiple features at the
    same time:
    
    - Multiple coloring rules per line (this was a doozy).
    - Two columns with colors next to each other.
    - Text with its own newlines isn't rewrapped.
    - It still wraps if it overflows the cell.
    - Bovine readiness and international spirit.
    """
    __name = "moo"

    def render(self, renderer):
        renderer.table_header([
            dict(name="Dogma", width=35, style="full"),
            dict(name="Bessy", width=65, type="bool", style="cow"),
            dict(name="Pilsner", width=50, style="full"),
            dict(name="Nowrap", width=10, nowrap=True)])

        beer = (
            "                /\                      \n"
            "               / |\                     \n"
            "              /  | \                    \n"
            "             /   |  \                   \n"
            "            /____|   \                  \n"
            "           / \    \   \                 \n"
            "          /   \    \  /                 \n"
            "         /     \    \/                  \n"
            "        /       \   /                   \n"
            "       /         \ /                    \n"
            "      /           v                     \n"
            "     /               ( o )o)            \n"
            "    /               ( o )o )o)          \n"
            "                  (o( ~~~~~~~~o         \n"
            "                  ( )' ~~~~~~~' _       \n"                  
            "                    o|   o    |-. \\     \n"                  
            "                    o|     o  |  \\ \\    \n"                  
            "                     | .      |  | |    \n"                  
            "                    o|   .    |  / /    \n"          
            "                     |  .  .  |._ /     \n"          
            "                     .========.         \n")          

        beer_highlights = [(16, 18, "CYAN", None),
                           (55, 58, "CYAN", None),
                           (94, 98, "CYAN", None),
                           (133, 139, "CYAN", None),
                           (172, 179, "CYAN", None),
                           (213, 220, "RED", None),
                           (254, 261, "RED", None),
                           (295, 301, "RED", None),
                           (336, 341, "RED", None),
                           (377, 380, "RED", None),
                           (418, 419, "RED", None),
                           
                           (461, 468, "BLACK", "WHITE"),
                           (500, 510, "BLACK", "WHITE"),
                           (538, 551, "BLACK", "WHITE"),
                           (578, 591, "BLACK", "WHITE"),
                           
                           (620, 621, "BLACK", "WHITE"),
                           (660, 661, "BLACK", "WHITE"),
                           (740, 741, "BLACK", "WHITE"),
                           
                           (621, 631, "WHITE", 220),
                           (661, 671, "WHITE", 220),
                           (701, 711, "WHITE", 220),
                           (741, 751, "WHITE", 220),
                           (781, 791, "WHITE", 220),
                           (822, 830, "WHITE", 220)]

        renderer.table_row(
            ("This is a renderer stress-test. The flags should have correct"
             " colors, the beer should be yellow and the cell on the left"
             " should not bleed into the cell on the right.\n"
             "This is a really "
             "long column of text with its own newlines in it!\n"
             "This bovine experience has been brought to you by Rekall."),
            True,
            utils.AttributedString(beer, beer_highlights),
            ("This is a fairly long line that shouldn't get wrapped.\n"
             "The same row has another line that shouldn't get wrapped."))
        
        renderer.section("Heatmap test:")
        values = []
        for digit in itertools.islice(colors.EulersDecimals(), 0xff):
            values.append(dict(heat=float(digit + 1) * .1, value=digit))

        randomized = visual_aides.Heatmap(
            caption="Offset (p)",
            # Some of the below xs stand for eXtreme. The other ones just
            # look cool.
            headers=["%0.2x" % x for x in xrange(0, 0xff, 0x10)],
            row_headers=["0x%0.6x" % x for x
                         in xrange(0x0, 0xfffff, 0x10000)],
            values=values,
            greyscale=False)
        
        gradual = visual_aides.Heatmap(
            caption="Offset (v)",
            headers=["%0.2x" % x for x in xrange(0, 0xff, 0x10)],
            row_headers=["0x%0.6x" % x for x
                         in xrange(0x0, 0xfffff, 0x10000)],
            values=[dict(value="%x" % x, heat=x / 255.0) for x in xrange(256)],
            greyscale=False)
        
        ranges_legend = visual_aides.MapLegend([
            ("A", "kEfiACPIMemoryNVS", (0x00, 0xff, 0x00)),
            ("A", "kEfiACPIReclaimMemory", (0xc7, 0xff, 0x50)),
            ("Bc", "kEfiBootServicesCode", (0xff, 0xc7, 0x00)),
            ("Bd", "kEfiBootServicesData", (0xff, 0x00, 0x00)),
            ("M", "kEfiConventionalMemory", (0xff, 0xff, 0xff)),
            ("Ec", "kEfiLoaderCode", (0x00, 0xff, 0xff)),
            ("Ed", "kEfiLoaderData", (0x00, 0x00, 0xff)),
            ("X", "kEfiReservedMemoryType", (0x00, 0x00, 0x00)),
            ("Rc", "kEfiRuntimeServicesCode", (0xff, 0x00, 0xff)),
            ("Rd", "kEfiRuntimeServicesData", (0xff, 0x00, 0x50))])
        
        ranges = visual_aides.Heatmap.from_memory_ranges(
            caption="Offset (p)",
            legend=ranges_legend,
            ranges=[("kEfiConventionalMemory", 0x000000000000, 0x0000000a0000),
                    ("kEfiConventionalMemory", 0x000000100000, 0x000002000000),
                    ("kEfiBootServicesData", 0x000002000000, 0x000002600000),
                    ("kEfiConventionalMemory", 0x000002600000, 0x000008d00000),
                    ("kEfiLoaderData", 0x000008d00000, 0x000008d13000),
                    ("kEfiConventionalMemory", 0x000008d13000, 0x000008e00000),
                    ("kEfiLoaderData", 0x000008e00000, 0x0000093a9000),
                    ("kEfiConventionalMemory", 0x0000093a9000, 0x000009400000),
                    ("kEfiLoaderData", 0x000009400000, 0x00000ab65000),
                    ("kEfiRuntimeServicesCode", 0x00000ab65000, 0x00000ab72000),
                    ("kEfiRuntimeServicesCode", 0x00000ab72000, 0x00000aba2000),
                    ("kEfiRuntimeServicesData", 0x00000aba2000, 0x00000abc6000),
                    ("kEfiRuntimeServicesData", 0x00000abc6000, 0x00000abe6000),
                    ("kEfiLoaderData", 0x00000abe6000, 0x00000abe8000),
                    ("kEfiConventionalMemory", 0x00000abe8000, 0x000015000000),
                    ("kEfiBootServicesData", 0x000015000000, 0x000015020000),
                    ("kEfiConventionalMemory", 0x000015020000, 0x000016dc2000),
                    ("kEfiBootServicesData", 0x000016dc2000, 0x0000171a5000),
                    ("kEfiConventionalMemory", 0x0000171a5000, 0x000017363000),
                    ("kEfiLoaderCode", 0x000017363000, 0x0000173e0000),
                    ("kEfiConventionalMemory", 0x0000173e0000, 0x000017422000),
                    ("kEfiBootServicesData", 0x000017422000, 0x00001745b000),
                    ("kEfiLoaderCode", 0x00001745b000, 0x00001745c000),
                    ("kEfiBootServicesData", 0x00001745c000, 0x0000179de000),
                    ("kEfiACPIReclaimMemory", 0x0000179de000, 0x0000179df000),
                    ("kEfiConventionalMemory", 0x0000179df000, 0x0000179ec000),
                    ("kEfiBootServicesData", 0x0000179ec000, 0x000017aec000),
                    ("kEfiConventionalMemory", 0x000017aec000, 0x000017b0e000),
                    ("kEfiBootServicesData", 0x000017b0e000, 0x000017b10000),
                    ("kEfiConventionalMemory", 0x000017b10000, 0x000017b12000),
                    ("kEfiBootServicesData", 0x000017b12000, 0x0000189ec000),
                    ("kEfiConventionalMemory", 0x0000189ec000, 0x0000189ef000),
                    ("kEfiBootServicesCode", 0x0000189ef000, 0x000018b6c000),
                    ("kEfiConventionalMemory", 0x000018b6c000, 0x000018b9c000),
                    ("kEfiConventionalMemory", 0x000018b9c000, 0x000018bc0000),
                    ("kEfiReservedMemoryType", 0x000018bc0000, 0x000018bc4000),
                    ("kEfiACPIReclaimMemory", 0x000018bc4000, 0x000018bcc000),
                    ("kEfiACPIMemoryNVS", 0x000018bcc000, 0x000018bd0000),
                    ("kEfiBootServicesData", 0x000018bd0000, 0x000018fd0000),
                    ("kEfiConventionalMemory", 0x000018fd0000, 0x000018ff0000)])
        
        renderer.table_header([dict(name="Random Heatmap", style="full",
                                    width=60, align="c"),
                               dict(name="Gradual Heatmap", style="full",
                                    width=60, align="c"),
                               dict(name="Legend", style="full",
                                    orientation="horizontal")])
        renderer.table_row(randomized, gradual, visual_aides.HEATMAP_LEGEND)

        renderer.table_header([dict(name="Greyscale Random", style="full",
                                    width=60, align="c"),
                               dict(name="Memory Ranges", style="full",
                                    width=80, align="c"),
                               dict(name="Ranges Legend", style="full",
                                    width=30, orientation="vertical")])

        randomized.greyscale = True
        renderer.table_row(randomized, ranges, ranges_legend)
