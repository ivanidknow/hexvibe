// Vulnerable: VUL-CVE-2008-4201
** For more info contact Nero AG through Mpeg4AAClicense@nero.com.
**
** $Id: audio.c,v 1.28 2007/11/01 12:33:29 menno Exp $
**/

...
void close_audio_file(audio_file *aufile)
{
    if (aufile->fileType == OUTPUT_WAV)
    {
        fseek(aufile->sndfile, 0, SEEK_SET);
...
            sbr->l_A[ch] = sbr->bs_pointer[ch] - 1;
    } else {
        if (sbr->bs_pointer[ch] == 0)
