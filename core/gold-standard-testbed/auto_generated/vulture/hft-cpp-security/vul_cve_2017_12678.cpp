// Vulnerable: VUL-CVE-2017-12678
{
    TextIdentificationFrame *tdrc =
      static_cast<TextIdentificationFrame *>(tag->frameList("TDRC").front());
    UnknownFrame *tdat = static_cast<UnknownFrame *>(tag->frameList("TDAT").front());

...
    UnknownFrame *tdat = static_cast<UnknownFrame *>(tag->frameList("TDAT").front());

    if(tdrc->fieldList().size() == 1 &&
       tdrc->fieldList().front().size() == 4 &&
       tdat->data().size() >= 5)
