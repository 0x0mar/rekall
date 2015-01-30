# -*- coding: utf-8 -*-

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

"""This module implements various visual aides and their renderers."""

import itertools
import logging
import math
import StringIO

from rekall import utils

from rekall.ui import colors
from rekall.ui import text


class Heatmap(object):
    """Represents a map of memory regions with various highliting.

    Heatmaps are divided into rows with constant number of cells, each
    with individual highlighting rules (mostly coloring).

    Arguments:
    ==========

    headers: As table headers.
    row_headers: (Optional) First column with row headers.
    caption: (Optional) Should describe relationship between headers
             and row headers. Rendering is up to the renderer.
    greyscale: If False (default) heatmap intensity values will be translated
               into colors with increasing hue. If True, shades of grey will
               be used instead with varying luminosity.

               NOTE: This flag does not affect heatmaps that don't use heat
               (intensity) values but specify colors manually (such as
               highlighting memory ranges.)
    """

    def __init__(self, headers, row_headers=None, values=None,
                 caption=None, rows=None, greyscale=False):
        self.headers = headers
        self.row_headers = row_headers or ()
        self.caption = caption or "-"
        self.greyscale = greyscale

        if rows:
            self.rows = []
            for n, header in enumerate(self.row_headers):
                self.rows.append([header] + rows[n])
            else:
                self.rows = rows
        elif values:
            # Divide values into rows, each the same length as the number
            # of headers.
            values = list(values)
            per_row = len(self.headers)
            row_count, r = divmod(len(values), per_row)
            if r:
                row_count += 1
            
            chunks = [iter(values)] * per_row
            if self.row_headers:
                self.rows = list(itertools.izip_longest(
                    row_headers, *chunks))
            else:
                self.rows = list(itertools.izip_longest(*chunks))

        else:
            raise ValueError("Must provide rows or values.")

    @staticmethod
    def _headers_for_memory(size, column_count, cell_size, offset=0x0):
        htpl = "+%%0.%dx" % len("%x" % cell_size)
        headers = [htpl % x for x
                   in xrange(0, cell_size * column_count, cell_size)]

        count_rows, r = divmod(size, column_count * cell_size)
        if r:
            count_rows += 1

        row_headers = ["0x%x " % (x * cell_size * column_count)
                       for x in xrange(count_rows)]

        return headers, row_headers

    @classmethod
    def from_memory_chunks(cls, chunks, chunk_size=0x1000, page_size=0x1000,
                           caption="Offset", offset=0x0):
        size = chunk_size * page_size
        htpl = "%%0.%dx" % len("%x" % size)
        headers = [htpl % x for x in xrange(0, size * 0x10, size)]

        count_rows = len(chunks) / 0x10
        
        row_headers = ["0x%x" % (x * chunk_size * 0x10)
                       for x in xrange(count_rows)]

        tpl = "%%d/%d" % chunk_size
        values = [dict(heat=float(x) / chunk_size, value=tpl % x)
                  for x in chunks]
        return cls(caption=caption, values=values, headers=headers,
                   row_headers=row_headers)

    @classmethod
    def from_memory_ranges(cls, ranges, legend, size=None, offset=0x0,
                           caption="Offset", resolution=0x100000,
                           cell_len=6, blend=True, column_count=8):
        """Build a map from supplied ranges with supplied colors.

        Arguments:
        ==========

        ranges: Tuple of ((str) name, (int) start, (int) end).
                The name of a range is used to lookup colors and sigils in
                legend, so it has to be the same.
        legend: Instance of MapLegend - see doc there.
        size: The largest address in the map. Optional - if not supplied,
              the map will show up to the end of the highest range.
        offset: The lowst address in the map. Optional - if not supplied, map
                will start at zero. TODO (adamsh): this value isn't respected.
        caption: Explanation of what the map is showing. Default is 'Offset'
                 and is typically overriden to something like 'Offset (v)'.
        resolution: How many bytes one cell in the map represents.
        cell_len: How long of a string is permitted in the cells themselves.
                  This value is important because the cells show sigils
                  (see MapLegend) in order of representation.
        blend: Should the map attempt to blend the color of overlapping ranges?
               If False the map basically becomes a painter's algorithm.
        column_count: How many columns wide should the map be? Lowering this
                      value will result in more rows.
        """
        ranges = sorted(ranges, key=lambda x: x[1])

        if not size:
            size = ranges[-1][2]

        cell_count = size / resolution + 1
        values = [{"_weight": 0.0, "_sigils": dict(), "value": "-",
                   "_rgb": (0, 0, 0)}
                  for _ in xrange(cell_count)]

        headers, row_headers = cls._headers_for_memory(
            size=size, column_count=column_count, cell_size=resolution,
            offset=offset)

        for title, start, end in ranges:
            for chunk in xrange(start, end, resolution):
                idx = chunk / resolution

                # See how much of this is in this chunk:
                chunk_start = max(chunk, start)
                chunk_end = min(chunk+resolution, end)
                chunk_size = chunk_end - chunk_start
                chunk_weight = resolution / float(chunk_size)

                value = values[idx]
                weight = value["_weight"]
                rgb = legend.colors.get(title, (0, 0, 0))

                if blend and weight:
                    rgb = colors.BlendRGB(x=value["_rgb"],
                                          y=rgb,
                                          wx=weight,
                                          wy=chunk_weight)

                sigils = value["_sigils"]
                sigil = legend.sigils.get(title)
                if not sigil:
                    sigil = "?"
                    logging.warning("Unknown memory region %s!", title)

                sigils.setdefault(sigil, 0.0)
                sigils[sigil] += chunk_weight

                value["_weight"] = weight + chunk_weight
                value["_rgb"] = rgb
        
        for value in values:
            value["bg"] = colors.RGBToXTerm(*value["_rgb"])
            room = cell_len
            string = ""
            for sigil, w in sorted(
                    value["_sigils"].iteritems(), key=lambda x: x[1],
                    reverse=True):

                if len(sigil) < room:
                    string += sigil
                    room -= len(sigil)

                if not room:
                    break
            
            value["value"] = string or "-"

        return cls(values=values, caption=caption, headers=headers,
                   row_headers=row_headers)

    @property
    def values(self):
        if self.row_headers:
            slicer = lambda row: row[1:]
        else:
            slicer = lambda row: row

        for row in self.rows:
            for value in slicer(row):
                yield value

    @property
    def columns(self):
        columns = []

        if self.row_headers:
            width = max([len(x) for x in self.row_headers])
            columns.append(dict(name=self.caption, width=width, align="c"))

        for header in self.headers:
            columns.append(dict(name="%s " % header))

        return columns


class MapLegend(object):
    """Describes a (heat) map using colors, sigils and optional description.

    Attributes:
    notes: Optional text to display next to the legend (depends on renderer.)
    legend: List of tuples of ((str) sigil, (str) name, (r,g,b) color).

    Sigils, names and colors:
    A name is a long, descriptive title of each range. E.g. "ACPI Memory"
    A sigil is a short (len 1-2) symbol which will be displayed within each
    cell for more clarity (by some renderers). E.g. "Ac"
    A color is a tuple of (red, green, blue) and is exactly what it sounds
    like.
    """
    def __init__(self, legend, notes=None):
        self.notes = notes
        self.legend = legend
        self.colors = {}
        self.sigils = {}
        for sigil, title, rgb in legend:
            self.colors[title] = rgb
            self.sigils[title] = sigil


HEATMAP_LEGEND = MapLegend(
    [(None, "%.1f" % (x / 10.0), colors.HeatToRGB(x / 10.0))
     for x in xrange(11)])


class HeatmapTextRenderer(text.TextObjectRenderer):
    renders_type = "Heatmap"

    def render_address(self, *_, **__):
        raise NotImplementedError()

    def render_full(self, target, **options):
        headers = []
        if target.row_headers:
            headers.append(text.Cell(target.caption or "-", padding=1))
        headers += [text.Cell(x, align="c", padding=1) for x in target.headers]

        rows = [text.JoinedCell(*headers, tablesep="")]
        for row in target.rows:
            cells = []
            for value in row:
                if not isinstance(value, dict):
                    # This is not a heat value - probably a row header or
                    # something.
                    cells.append(text.Cell(value or "", align="r", padding=1))
                    continue

                fg = value.get("fg")
                bg = value.get("bg")
                heat = value.get("heat")
                if heat and not bg:
                    bg = colors.HeatToXTerm(heat, greyscale=target.greyscale)

                if bg and not fg:
                    fg = colors.XTermTextForBackground(bg)

                cell = text.Cell(
                    value=unicode(value.get("value", "-")),
                    highlights=[dict(bg=bg, fg=fg, start=0, end=-1, bold=True)],
                    colorizer=self.renderer.colorizer,
                    padding=1)
                cells.append(cell)
            
            rows.append(text.JoinedCell(*cells, tablesep=""))
        return text.StackedCell(*rows)

    def render_value(self, *_, **__):
        raise NotImplementedError

    def render_compact(self, target, **_):
        return text.Cell(repr(target))


class MapLegendRenderer(text.TextObjectRenderer):
    renders_type = "MapLegend"

    def render_full(self, target, **options):
        orientation = options.pop("orientation", "vertical")
        
        cells = []
        for sigil, description, bg in target.legend:
            bg = colors.RGBToXTerm(*bg)
            fg = colors.XTermTextForBackground(bg)
            if sigil:
                title = "%s (%s)" % (description, sigil)
            else:
                title = description
            cell = text.Cell(
                value=title,
                highlights=[dict(bg=bg, fg=fg, start=0, end=-1)],
                colorizer=self.renderer.colorizer,
                padding=2,
                align="c")
            cells.append(cell)

        if orientation == "vertical":
            legend = text.StackedCell(*cells, table_align=False)
        elif orientation == "horizontal":
            legend = text.JoinedCell(*cells)
        else:
            raise ValueError("Invalid orientation %s." % orientation)
        
        if target.notes:
            cell = text.Cell(target.notes)
            legend = text.StackedCell(cell, legend, table_align=False)
        
        return legend

    def render_address(self, *_, **__):
        raise NotImplementedError()
    
    def render_value(self, *_, **__):
        raise NotImplementedError()
    
    def render_compact(self, target, **_):
        return text.Cell(repr(target))
