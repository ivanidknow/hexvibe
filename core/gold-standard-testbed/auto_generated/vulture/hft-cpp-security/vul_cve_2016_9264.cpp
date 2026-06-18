// Vulnerable: VUL-CVE-2016-9264
#define MP3_SAMPLERATE       0x00000C00
#define MP3_SAMPLERATE_SHIFT 10

int mp1_samplerate_table[] = { 44100, 48000, 32000 };
...
#define MP3_SAMPLERATE_SHIFT 10

int mp1_samplerate_table[] = { 44100, 48000, 32000 };
int mp2_samplerate_table[] = { 22050, 24000, 16000 }; /* is this right?? */
int mp25_samplerate_table[] = { 11025, 12000, 8000 }; /* fewer samples?? */

...
    samplerate_idx = (flags & MP3_SAMPLERATE) >> MP3_SAMPLERATE_SHIFT;

    channels = ((flags & MP3_CHANNEL) == MP3_CHANNEL_MONO) ? 1 : 2;
