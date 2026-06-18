// Vulnerable: VUL-CVE-2017-7578
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
...
#include <stdlib.h>
#include <string.h>
#include "blocks/blocktypes.h"
#include "abctypes.h"
...
parseSWF_GLYPHENTRY (FILE * f, SWF_GLYPHENTRY *gerec, int glyphbits, int advancebits)
...
  int NumGlyphs;
  UI16 *OffsetTable;
  SWF_SHAPE *GlyphShapeTable;
