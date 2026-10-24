<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# local tools

### usually for rounder corner image


```bash
magick input.png \( -size 1254x1254 xc:none -fill white -draw 'roundrectangle 0,0 1253,1253 68,68' \) -alpha off -compose CopyOpacity -composite output.png

```
